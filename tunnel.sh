#!/bin/bash
export BASTION_HOST="vm.host.net"
export TUNNEL_USER="varun"
# Define the port range for the tunnel
PORT_RANGE_START=49000
PORT_RANGE_END=65535
# Maximum number of attempts to find an available port
MAX_ATTEMPTS=10

# Function to check if a port is available
is_port_in_use() {
  local port=$1
  lsof -i :$port >/dev/null 2>&1
  return $?
}

# Function to generate a random port in a specified range
generate_random_port() {
  echo $(( ( RANDOM % ($2 - $1 + 1) ) + $1 ))
}

# Function to get an available port within the specified range
get_random_port() {
  local attempts=0
  while [ $attempts -lt $MAX_ATTEMPTS ]; do
    local port=$(generate_random_port $PORT_RANGE_START $PORT_RANGE_END)
    if ! is_port_in_use $port; then
      echo $port
      return 0
    fi
    ((attempts++))
  done
  echo "No available port to create a tunnel."
  exit 1
}

create_tunnel() {
  local local_port=$1
  local db_host=$2
  local tunnel_socket="/tmp/ssh_tunnel_$local_port"
  local ssh_output_file="/tmp/ssh_output_$local_port"

  if is_port_in_use $local_port; then
      echo "The port $local_port is already in use"
      exit 1
  fi

  # Set up a trap to ensure the tunnel is closed on script exit
  trap 'close_tunnel "$local_port";' EXIT ERR
  
  # Run ssh in the background and store the process ID in a variable
  ssh -nNT -L $local_port:$db_host:5432 $TUNNEL_USER@$BASTION_HOST -M -S $tunnel_socket > $ssh_output_file 2>&1 &

  ssh_pid=$!

  sleep 10 # Adjust the sleep duration as needed

  # Capture the output from the temporary file
  ssh_output=$(cat $ssh_output_file)

  if [ -z "$ssh_output" ]; then
    echo "SSH tunnel created successfully on local port $local_port."
    echo $local_port
  else
    # Check if the error message contains "Permission denied"
    if echo "$ssh_output" | grep -q "Permission denied"; then
      echo "Permission denied. Check your SSH key or credentials."
    else
      echo "Failed to create SSH tunnel. Error: $ssh_output"
    fi
    exit 1
  fi
}

# Function to close the SSH tunnel on a specific local port
close_tunnel() {
  local local_port=$1
  tunnel_socket="/tmp/ssh_tunnel_${local_port}"
  
  # Check if the tunnel is already running
  if [ -S $tunnel_socket ]; then
    # Attempt to connect to the local port using nc
    if nc -z localhost $local_port; then
      # Close the SSH tunnel by sending an exit command to the master process
      ssh -S $tunnel_socket -O exit $BASTION_HOST
      echo "Closed tunnel on local port $local_port."
    else
      echo "Tunnel on local port $local_port is not responding as expected."
    fi
  else
    echo "Tunnel on local port $local_port not found."
  fi
}

# Example usage:
# create_tunnel "port" "your_db_host"
# close_tunnel "port"
