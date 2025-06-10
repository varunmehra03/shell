#!/usr/bin/env python3
# Example: ./redis-connectivity.py --host localhost --port 6380 --ssl
import argparse
import socket
import sys
import time
from datetime import datetime

import redis

# Optional imports - won't fail if not available
try:
    import boto3

    BOTO3_AVAILABLE: bool = True
except ImportError:
    BOTO3_AVAILABLE: bool = False


def get_elasticache_endpoint(cluster_id, region=None):
    """Get the ElastiCache endpoint for a given cluster ID using boto3.

    Args:
        cluster_id (str): ElastiCache cluster identifier
        region (str): AWS region (if None, uses default from AWS config)

    Returns:
        tuple: (endpoint, port, engine) or (None, None, None) if cluster not found
    """
    if not BOTO3_AVAILABLE:
        print("ERROR: boto3 is required for AWS ElastiCache lookup.")
        print("Install it with: pip install boto3")
        return None, None, None

    try:
        print(f"Looking up ElastiCache cluster with ID: {cluster_id}")

        # Create ElastiCache client
        elasticache = boto3.client("elasticache", region_name=region)

        # First check if it's a replication group (Redis cluster mode enabled or disabled)
        try:
            response = elasticache.describe_replication_groups(
                ReplicationGroupId=cluster_id
            )

            if (
                response
                and "ReplicationGroups" in response
                and response["ReplicationGroups"]
            ):
                group = response["ReplicationGroups"][0]

                # For cluster mode enabled, use the configuration endpoint
                if "ConfigurationEndpoint" in group and group["ConfigurationEndpoint"]:
                    endpoint = group["ConfigurationEndpoint"]["Address"]
                    port = group["ConfigurationEndpoint"]["Port"]
                    return endpoint, port, "redis"

                # For cluster mode disabled, use the primary endpoint
                if "NodeGroups" in group and group["NodeGroups"]:
                    endpoint = group["NodeGroups"][0]["PrimaryEndpoint"]["Address"]
                    port = group["NodeGroups"][0]["PrimaryEndpoint"]["Port"]
                    return endpoint, port, "redis"

        except elasticache.exceptions.ReplicationGroupNotFoundFault:
            # Not a replication group, will try as a cache cluster
            pass

        # If not found as replication group, try as a cache cluster (older style)
        response = elasticache.describe_cache_clusters(
            CacheClusterId=cluster_id, ShowCacheNodeInfo=True
        )

        if response and "CacheClusters" in response and response["CacheClusters"]:
            cluster = response["CacheClusters"][0]
            engine = cluster["Engine"]

            if "CacheNodes" in cluster and cluster["CacheNodes"]:
                endpoint = cluster["CacheNodes"][0]["Endpoint"]["Address"]
                port = cluster["CacheNodes"][0]["Endpoint"]["Port"]
                return endpoint, port, engine

        print(f"ERROR: Could not find ElastiCache cluster with ID: {cluster_id}")
        return None, None, None

    except Exception as e:
        print(f"ERROR: Failed to lookup ElastiCache endpoint: {e}")
        print(
            "Make sure you have the boto3 package installed and valid AWS credentials configured."
        )
        return None, None, None


def test_redis_connection(
    host,
    port=6379,
    password=None,
    ssl=False,
    ssl_ca_certs=None,
    timeout=5,
    cluster_mode=False,
    skip_dns_check=False,
    tls_cert=None,
    tls_key=None,
):
    """Test connectivity to a Redis instance (AWS ElastiCache or self-hosted).

    Args:
        host (str): Redis host/endpoint
        port (int): Redis port (default: 6379)
        password (str): Redis password if AUTH is enabled
        ssl (bool): Whether to use SSL/TLS connection
        ssl_ca_certs (str): Path to CA certificate file for SSL
        timeout (int): Connection timeout in seconds
        cluster_mode (bool): Whether to use Redis cluster mode client
        skip_dns_check (bool): Skip DNS resolution check (for local connections)
        tls_cert (str): Path to client certificate file for TLS
        tls_key (str): Path to client key file for TLS

    Returns:
        bool: True if connection successful, False otherwise
    """
    start_time = time.time()
    print(
        f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Testing connection to Redis at {host}:{port}"
    )

    # First check if we can resolve the hostname (unless it's localhost or an IP)
    if not skip_dns_check and host not in ("localhost", "127.0.0.1", "::1"):
        try:
            print(f"Resolving hostname {host}...")
            ip_address = socket.gethostbyname(host)
            print(f"Hostname resolved to IP: {ip_address}")
        except socket.gaierror as e:
            print(f"ERROR: Could not resolve hostname: {e}")
            return False

    # Now check if the port is reachable
    if not skip_dns_check:
        try:
            connect_host = host
            print(f"Testing TCP connectivity to {connect_host}:{port}...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((connect_host, port))
            s.close()
            print("TCP connection successful!")
        except (socket.timeout, socket.error) as e:
            print(f"ERROR: Could not connect to port: {e}")
            return False

    # Now try to connect using the Redis client
    try:
        print("Establishing Redis connection...")

        # Configure Redis connection options
        connection_kwargs = {
            "host": host,
            "port": port,
            "socket_timeout": timeout,
            "socket_connect_timeout": timeout,
            "retry_on_timeout": True,
        }

        if password:
            connection_kwargs["password"] = password

        if ssl:
            connection_kwargs["ssl"] = True

            if ssl_ca_certs:
                connection_kwargs["ssl_ca_certs"] = ssl_ca_certs
            else:
                connection_kwargs["ssl_cert_reqs"] = None  # Don't validate certificates

            if tls_cert:
                connection_kwargs["ssl_certfile"] = tls_cert

            if tls_key:
                connection_kwargs["ssl_keyfile"] = tls_key

        # Create Redis client and test connection
        if cluster_mode:
            try:
                from redis.cluster import RedisCluster

                r = RedisCluster(**connection_kwargs)
                print("Connected using Redis Cluster client")
            except ImportError:
                print(
                    "WARNING: Redis cluster client not available, falling back to standard client"
                )
                r = redis.Redis(**connection_kwargs)
        else:
            r = redis.Redis(**connection_kwargs)

        # Try a PING command
        response = r.ping()
        if response:
            print("Redis PING successful!")

        # Try simple SET and GET operations
        test_key = "connectivity_test"
        test_value = f"test_{int(time.time())}"

        print(f"Attempting to SET key: {test_key}")
        r.set(test_key, test_value)

        print("Attempting to GET the key")
        retrieved_value = r.get(test_key)

        if retrieved_value.decode("utf-8") == test_value:
            print(f"Successfully retrieved value: {retrieved_value.decode('utf-8')}")
        else:
            print(
                f"WARNING: Retrieved value doesn't match: {retrieved_value.decode('utf-8')} != {test_value}"
            )

        # Clean up test key
        r.delete(test_key)
        print("Test key deleted")

        # Get server info
        try:
            info = r.info()
            print("\nRedis Server Info:")
            print(f"Redis Version: {info.get('redis_version')}")
            print(f"Uptime: {info.get('uptime_in_seconds')} seconds")
            print(f"Connected Clients: {info.get('connected_clients')}")
            print(f"Memory Used: {info.get('used_memory_human')}")

            # Check for cluster mode
            if "cluster_enabled" in info and info["cluster_enabled"] == 1:
                print("Cluster Mode: Enabled")
                try:
                    # Get cluster info if in cluster mode
                    cluster_info = r.cluster_info()
                    print(f"Cluster Size: {cluster_info.get('cluster_size')} nodes")
                    print(f"Cluster State: {cluster_info.get('cluster_state')}")
                except redis.exceptions.ResponseError:
                    # This could happen if connected to a single node in cluster mode
                    print("Note: Connected to a single node of a Redis cluster")
            else:
                print("Cluster Mode: Disabled")

            # Check for replication
            if "role" in info:
                print(f"Node Role: {info.get('role')}")
                if info.get("role") == "master":
                    print(f"Connected Slaves: {info.get('connected_slaves', 0)}")
                elif info.get("role") == "slave":
                    print(f"Master Host: {info.get('master_host', 'unknown')}")
                    print(f"Master Port: {info.get('master_port', 'unknown')}")

            # Check for keyspace stats
            if any(k.startswith("db") for k in info.keys()):
                print("\nKeyspace Stats:")
                for k in sorted(info.keys()):
                    if k.startswith("db"):
                        print(f"{k}: {info[k]}")
        except redis.exceptions.ResponseError as e:
            print(f"WARNING: Couldn't retrieve full server info: {e}")

        # Close connection
        r.close()

        elapsed_time = time.time() - start_time
        print(f"\n✅ Connection test SUCCESSFUL (took {elapsed_time:.2f} seconds)")
        return True

    except redis.exceptions.AuthenticationError:
        print("❌ Authentication failed. Check if a password is required.")
        return False
    except redis.exceptions.ConnectionError as e:
        print(f"❌ Connection error: {e}")
        return False
    except redis.exceptions.ResponseError as e:
        print(f"❌ Redis response error: {e}")
        return False
    except redis.exceptions.DataError as e:
        print(f"❌ Redis data error: {e}")
        return False
    except redis.exceptions.TimeoutError as e:
        print(f"❌ Redis timeout error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


def display_result_and_recommendations(success, host, port, engine):
    """Display results and provide recommendations for troubleshooting."""
    if success:
        print("\n==================================================")
        print(f"✅ Successfully connected to {engine} at {host}:{port}")
        print("==================================================")
    else:
        print("\n==================================================")
        print(f"❌ Failed to connect to {engine} at {host}:{port}")
        print("\nPossible issues and recommendations:")

        print(
            " 1. Network connectivity: Check firewall rules, security groups, and network ACLs"
        )
        print(" 2. Authentication: Verify the correct password/token is being used")
        print(
            " 3. TLS/SSL configuration: Ensure certificates are valid and properly configured"
        )
        print(
            " 4. Redis configuration: Check that the Redis server is configured to accept remote connections"
        )
        print(
            " 5. For AWS ElastiCache: Verify VPC, subnet, and security group configurations"
        )
        print("\nFor AWS ElastiCache troubleshooting resources:")
        print(
            " - https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Troubleshooting.html"
        )
        print("==================================================")


def main():
    parser = argparse.ArgumentParser(
        description="Test connectivity to Redis instances (local or AWS ElastiCache)"
    )

    # Connection method group - multiple ways to connect
    connection_group = parser.add_mutually_exclusive_group(required=True)
    connection_group.add_argument(
        "--host", help="Redis host/endpoint (direct connection)"
    )
    connection_group.add_argument(
        "--cluster-id", help="AWS ElastiCache cluster ID (will look up endpoint)"
    )

    # Optional AWS parameters
    aws_group = parser.add_argument_group("AWS options")
    aws_group.add_argument("--region", help="AWS region (if using --cluster-id)")
    aws_group.add_argument("--profile", help="AWS profile name to use")

    # Connection parameters
    conn_group = parser.add_argument_group("Connection options")
    conn_group.add_argument(
        "--port", type=int, help="Port number (default: 6379 for Redis)"
    )
    conn_group.add_argument(
        "--password", help="Redis password/auth token if AUTH is enabled"
    )
    conn_group.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Connection timeout in seconds (default: 5)",
    )
    conn_group.add_argument(
        "--engine",
        default="redis",
        choices=["redis"],
        help="Explicitly set the engine type (default: redis)",
    )
    conn_group.add_argument(
        "--skip-dns-check",
        action="store_true",
        help="Skip DNS and TCP connectivity checks (useful for local testing)",
    )

    # Redis specific options
    redis_group = parser.add_argument_group("Redis specific options")
    redis_group.add_argument(
        "--ssl", action="store_true", help="Use SSL/TLS connection"
    )
    redis_group.add_argument(
        "--ssl-ca-certs", help="Path to CA certificate file for SSL verification"
    )
    redis_group.add_argument(
        "--tls-cert", help="Path to client certificate file for TLS"
    )
    redis_group.add_argument("--tls-key", help="Path to client key file for TLS")
    redis_group.add_argument(
        "--cluster-mode",
        action="store_true",
        help="Use Redis cluster client mode (for Redis cluster)",
    )

    # Output options
    output_group = parser.add_argument_group("Output options")
    output_group.add_argument(
        "--quiet", action="store_true", help="Minimal output (errors only)"
    )

    args = parser.parse_args()

    # Configure boto3 if AWS features are being used
    if args.cluster_id or args.profile:
        if not BOTO3_AVAILABLE:
            print("ERROR: The boto3 package is required for AWS ElastiCache features.")
            print("Please install it with: pip install boto3")
            return 1

        if args.profile:
            boto3.setup_default_session(profile_name=args.profile)

    # Determine endpoint to connect to
    if args.cluster_id:
        endpoint, port, engine = get_elasticache_endpoint(args.cluster_id, args.region)
        if not endpoint:
            return 1
    else:
        endpoint = args.host
        port = args.port
        engine = args.engine

        # Try to guess the engine if not explicitly specified
        if not engine:
            if port == 6379:
                engine = "redis"
            else:
                # Default to redis if we can't determine
                engine = "redis"
                print(
                    f"No engine specified and couldn't determine from port. Defaulting to {engine}."
                )

    # Override port if explicitly provided
    if args.port:
        port = args.port
    elif not port:
        # Set default port based on engine
        port = 6379 if engine == "redis" else 11211

    if not args.quiet:
        print(f"Engine detected/specified: {engine}")
        print(f"Connecting to: {endpoint}:{port}")

    # Test the appropriate connection based on engine type
    if engine == "redis":
        success = test_redis_connection(
            host=endpoint,
            port=port,
            password=args.password,
            ssl=args.ssl,
            ssl_ca_certs=args.ssl_ca_certs,
            timeout=args.timeout,
            cluster_mode=args.cluster_mode,
            skip_dns_check=args.skip_dns_check,
            tls_cert=args.tls_cert,
            tls_key=args.tls_key,
        )
    else:
        print(f"Unsupported engine type: {engine}")
        success = False

    # Display results and recommendations
    if not args.quiet:
        display_result_and_recommendations(success, endpoint, port, engine)

    # Exit with appropriate status code
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
