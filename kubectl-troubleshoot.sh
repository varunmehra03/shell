#!/bin/bash

# kubectl-troubleshoot.sh - A comprehensive Kubernetes troubleshooting script
# Usage: ./kubectl-troubleshoot.sh <namespace>

set -e

# Colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if kubectl is installed
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}Error: kubectl is not installed or not in PATH${NC}"
    exit 1
fi

# Check if namespace is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}Error: Namespace is required${NC}"
    echo "Usage: $0 <namespace>"
    exit 1
fi

NAMESPACE=$1
OUTPUT_DIR="k8s-troubleshoot-${NAMESPACE}-$(date +%Y%m%d-%H%M%S)"

# Check if namespace exists
echo -e "${BLUE}Checking if namespace ${NAMESPACE} exists...${NC}"
if ! kubectl get namespace ${NAMESPACE} &> /dev/null; then
    echo -e "${RED}Error: Namespace '${NAMESPACE}' does not exist${NC}"
    
    # List available namespaces to help the user
    echo -e "${YELLOW}Available namespaces:${NC}"
    kubectl get namespaces --no-headers | awk '{print $1}'
    exit 1
fi

# Create output directory
mkdir -p $OUTPUT_DIR

echo -e "${GREEN}=== Kubernetes Troubleshooting Tool ===${NC}"
echo -e "${GREEN}Namespace: ${NAMESPACE}${NC}"
echo -e "${GREEN}Output directory: ${OUTPUT_DIR}${NC}"
echo -e "${GREEN}=====================================${NC}"

# Helper function to run kubectl commands and save output
k8s_dump() {
    local resource=$1
    local command=$2
    local args=$3
    local output_file="${OUTPUT_DIR}/${resource}-${command}.txt"
    
    echo -e "${BLUE}Collecting ${resource} ${command}...${NC}"
    kubectl ${command} ${resource} -n ${NAMESPACE} ${args} > "${output_file}" 2>&1 || echo -e "${YELLOW}Warning: Error collecting ${resource} ${command}${NC}" >> "${output_file}"
}

# Helper function to get logs
get_logs() {
    local pod=$1
    local container_flag=""
    local output_file="${OUTPUT_DIR}/logs-${pod}.txt"
    
    # Check if the pod has multiple containers
    local containers=$(kubectl get pod ${pod} -n ${NAMESPACE} -o jsonpath='{.spec.containers[*].name}' 2>/dev/null)
    if [[ $(echo $containers | wc -w) -gt 1 ]]; then
        echo -e "${BLUE}Pod ${pod} has multiple containers. Collecting logs for each container...${NC}"
        for container in $containers; do
            echo -e "${BLUE}Collecting logs for pod ${pod}, container ${container}...${NC}"
            kubectl logs -n ${NAMESPACE} ${pod} -c ${container} --tail=1000 > "${output_file}.${container}" 2>&1 || \
                echo -e "${YELLOW}Warning: Error collecting logs for ${pod}:${container}${NC}" >> "${output_file}.${container}"
            
            # Also get previous logs if available
            kubectl logs -n ${NAMESPACE} ${pod} -c ${container} --tail=1000 --previous > "${output_file}.${container}.previous" 2>&1 || true
        done
    else
        echo -e "${BLUE}Collecting logs for pod ${pod}...${NC}"
        kubectl logs -n ${NAMESPACE} ${pod} --tail=1000 > "${output_file}" 2>&1 || \
            echo -e "${YELLOW}Warning: Error collecting logs for ${pod}${NC}" >> "${output_file}"
        
        # Also get previous logs if available
        kubectl logs -n ${NAMESPACE} ${pod} --tail=1000 --previous > "${output_file}.previous" 2>&1 || true
    fi
}

# STAGE 1: Collect basic namespace and cluster information
echo -e "${GREEN}[STAGE 1/5] Collecting basic namespace and cluster information...${NC}"

# Get namespace details
echo -e "${BLUE}Collecting namespace information...${NC}"
kubectl get namespace ${NAMESPACE} -o yaml > "${OUTPUT_DIR}/namespace-info.yaml"

# Get cluster-level information
echo -e "${BLUE}Collecting cluster-level information...${NC}"
kubectl cluster-info > "${OUTPUT_DIR}/cluster-info.txt" 2>&1
kubectl get nodes -o wide > "${OUTPUT_DIR}/nodes-info.txt" 2>&1

# Get events for this namespace (critical for troubleshooting)
echo -e "${BLUE}Collecting events...${NC}"
kubectl get events -n ${NAMESPACE} --sort-by='.lastTimestamp' > "${OUTPUT_DIR}/events.txt"

# STAGE 2: Check high-level resources (deployments, statefulsets, daemonsets)
echo -e "${GREEN}[STAGE 2/5] Checking high-level workload resources...${NC}"

# Collect information about workload controllers
for resource in deployments statefulsets daemonsets; do
    # Check if any resources of this type exist in the namespace
    if kubectl get ${resource} -n ${NAMESPACE} --no-headers 2>/dev/null | grep -q .; then
        k8s_dump "${resource}" "get" "--output wide"
        k8s_dump "${resource}" "describe" ""
    else
        echo -e "${YELLOW}No ${resource} found in namespace ${NAMESPACE}${NC}"
    fi
done

# STAGE 3: Check pods and their containers (the most common source of issues)
echo -e "${GREEN}[STAGE 3/5] Examining pods and containers...${NC}"

# Check if any pods exist in the namespace
if ! kubectl get pods -n ${NAMESPACE} --no-headers 2>/dev/null | grep -q .; then
    echo -e "${YELLOW}No pods found in namespace ${NAMESPACE}${NC}"
else
    # Collect pod information
    k8s_dump "pods" "get" "--output wide"
    k8s_dump "pods" "describe" ""
    
    # Get detailed pod status and conditions
    kubectl get pods -n ${NAMESPACE} -o=jsonpath='{range .items[*]}{.metadata.name}{": "}{.status.phase}{", Ready: "}{.status.containerStatuses[*].ready}{", Restarts: "}{.status.containerStatuses[*].restartCount}{"\n"}{end}' > "${OUTPUT_DIR}/pod-statuses.txt"
    
    # Identify problematic pods for focused investigation
    PROBLEM_PODS=$(kubectl get pods -n ${NAMESPACE} --no-headers | grep -v "Running\|Completed" | awk '{print $1}')
    if [ -n "$PROBLEM_PODS" ]; then
        echo -e "${YELLOW}Found problematic pods:${NC}"
        echo "$PROBLEM_PODS" | tee "${OUTPUT_DIR}/problem-pods.txt"
        
        # Prioritize logs from problematic pods
        for pod in $PROBLEM_PODS; do
            get_logs "$pod"
        done
    fi
    
    # Collect logs from all running pods
    RUNNING_PODS=$(kubectl get pods -n ${NAMESPACE} --no-headers | grep "Running" | awk '{print $1}')
    for pod in $RUNNING_PODS; do
        get_logs "$pod"
    done
fi

# STAGE 4: Check networking resources (services, ingress)
echo -e "${GREEN}[STAGE 4/5] Checking networking resources...${NC}"

# Check for services
if kubectl get services -n ${NAMESPACE} --no-headers 2>/dev/null | grep -q .; then
    k8s_dump "services" "get" "--output wide"
    k8s_dump "services" "describe" ""
    
    # Get endpoints to check if services are connected to pods
    k8s_dump "endpoints" "get" "--output wide"
    k8s_dump "endpoints" "describe" ""
else
    echo -e "${YELLOW}No services found in namespace ${NAMESPACE}${NC}"
fi

# Check for ingresses
if kubectl get ingress -n ${NAMESPACE} --no-headers 2>/dev/null | grep -q .; then
    k8s_dump "ingress" "get" "--output wide"
    k8s_dump "ingress" "describe" ""
else
    echo -e "${YELLOW}No ingresses found in namespace ${NAMESPACE}${NC}"
fi

# Check for network policies
if kubectl get networkpolicies -n ${NAMESPACE} --no-headers 2>/dev/null | grep -q .; then
    k8s_dump "networkpolicies" "get" "--output wide"
    k8s_dump "networkpolicies" "describe" ""
else
    echo -e "${YELLOW}No network policies found in namespace ${NAMESPACE}${NC}"
fi

# STAGE 5: Check configuration and permissions
echo -e "${GREEN}[STAGE 5/5] Checking configuration and permissions...${NC}"

# Check for configmaps
if kubectl get configmaps -n ${NAMESPACE} --no-headers 2>/dev/null | grep -q .; then
    k8s_dump "configmaps" "get" ""
    k8s_dump "configmaps" "describe" ""
else
    echo -e "${YELLOW}No configmaps found in namespace ${NAMESPACE}${NC}"
fi

# Check for secrets (don't show content for security)
if kubectl get secrets -n ${NAMESPACE} --no-headers 2>/dev/null | grep -q .; then
    k8s_dump "secrets" "get" ""
else
    echo -e "${YELLOW}No secrets found in namespace ${NAMESPACE}${NC}"
fi

# Check for service accounts and RBAC
if kubectl get serviceaccounts -n ${NAMESPACE} --no-headers 2>/dev/null | grep -q .; then
    k8s_dump "serviceaccounts" "get" ""
    k8s_dump "serviceaccounts" "describe" ""
    
    # Get roles and rolebindings
    k8s_dump "roles" "get" ""
    k8s_dump "rolebindings" "get" ""
else
    echo -e "${YELLOW}No service accounts found in namespace ${NAMESPACE}${NC}"
fi

# Check for resource quotas and limits
if kubectl get resourcequotas -n ${NAMESPACE} --no-headers 2>/dev/null | grep -q .; then
    k8s_dump "resourcequotas" "get" "--output wide"
    k8s_dump "resourcequotas" "describe" ""
fi

if kubectl get limitranges -n ${NAMESPACE} --no-headers 2>/dev/null | grep -q .; then
    k8s_dump "limitranges" "get" "--output wide"
    k8s_dump "limitranges" "describe" ""
fi

# Check for persistent volumes and claims
if kubectl get persistentvolumeclaims -n ${NAMESPACE} --no-headers 2>/dev/null | grep -q .; then
    k8s_dump "persistentvolumeclaims" "get" "--output wide"
    k8s_dump "persistentvolumeclaims" "describe" ""
fi

# Create a summary file with analysis
{
    echo -e "=== Kubernetes Troubleshooting Summary ==="
    echo -e "Namespace: $NAMESPACE"
    echo -e "Collection time: $(date)"
    echo -e "\n=== Resource Counts ==="
    
    # Count resources
    for resource in deployments statefulsets daemonsets pods services ingress configmaps secrets persistentvolumeclaims; do
        count=$(kubectl get ${resource} -n ${NAMESPACE} --no-headers 2>/dev/null | wc -l)
        echo -e "${resource}: ${count}"
    done
    
    echo -e "\n=== Pod Status Summary ==="
    kubectl get pods -n ${NAMESPACE} -o wide 2>/dev/null
    
    echo -e "\n=== Recent Warning Events ==="
    kubectl get events -n ${NAMESPACE} --sort-by='.lastTimestamp' --field-selector type=Warning 2>/dev/null | tail -10
    
    echo -e "\n=== Potential Issues ==="
    
    # Check for common pod issues
    if [ -f "${OUTPUT_DIR}/problem-pods.txt" ]; then
        echo -e "Problem pods found:"
        cat "${OUTPUT_DIR}/problem-pods.txt"
        
        # Extract specific error messages for problematic pods
        for pod in $(cat "${OUTPUT_DIR}/problem-pods.txt"); do
            echo -e "\nIssues with pod ${pod}:"
            grep -A 5 "Warning\|Error" "${OUTPUT_DIR}/pods-describe.txt" | grep -A 5 "${pod}" 2>/dev/null || echo "No specific error messages found"
        done
    else
        echo -e "No problematic pods detected"
    fi
    
    # Check for service connection issues
    echo -e "\nService connection check:"
    if [ -f "${OUTPUT_DIR}/endpoints-get.txt" ]; then
        empty_endpoints=$(grep "<none>" "${OUTPUT_DIR}/endpoints-get.txt" 2>/dev/null)
        if [ -n "$empty_endpoints" ]; then
            echo -e "Some services have no endpoints (not connected to any pods):"
            echo "$empty_endpoints"
        else
            echo -e "All services appear to have endpoints"
        fi
    fi
    
    # Check for resource constraints
    echo -e "\nResource constraint check:"
    if grep -q "exceeded quota" "${OUTPUT_DIR}/events.txt" 2>/dev/null; then
        echo -e "Resource quota exceeded errors detected"
        grep "exceeded quota" "${OUTPUT_DIR}/events.txt"
    else
        echo -e "No resource quota errors detected"
    fi
    
    echo -e "\nCommon error patterns in logs:"
    grep -l "Error\|Exception\|fail\|Fail\|ERROR\|FAIL" ${OUTPUT_DIR}/logs-* 2>/dev/null | while read logfile; do
        echo -e "\nErrors in $(basename "$logfile"):"
        grep -i "Error\|Exception\|fail\|Fail\|ERROR\|FAIL" "$logfile" | head -5
    done
    
    echo -e "\nFor detailed analysis, please examine the individual files in the output directory: ${OUTPUT_DIR}"
} > "${OUTPUT_DIR}/troubleshooting-summary.txt"

echo -e "${GREEN}=====================================${NC}"
echo -e "${GREEN}Troubleshooting data collection complete!${NC}"
echo -e "${GREEN}All information has been saved to: ${OUTPUT_DIR}${NC}"
echo -e "${GREEN}Summary file: ${OUTPUT_DIR}/troubleshooting-summary.txt${NC}"
echo -e "${GREEN}=====================================${NC}"

# Display the summary
echo -e "${BLUE}Displaying troubleshooting summary:${NC}"
cat "${OUTPUT_DIR}/troubleshooting-summary.txt"

echo -e "${GREEN}Next steps for troubleshooting:${NC}"
echo -e "1. Check the pod statuses and events for immediate issues"
echo -e "2. Examine logs of problematic pods in ${OUTPUT_DIR}/logs-*"
echo -e "3. Verify service connections with endpoints"
echo -e "4. Check for resource constraints or quota issues"
echo -e "5. Review configuration (configmaps, secrets) if application logic issues"
