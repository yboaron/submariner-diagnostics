#!/bin/bash
# Submariner Full Diagnostic Data Collector
# Uses subctl and kubectl to gather comprehensive troubleshooting data

# Don't use 'set -e' to avoid closing the shell on errors
# Instead, we'll handle errors explicitly

# Cleanup function for temporary files
cleanup_temp_files() {
    if [ "$CONTEXT_RENAMED" = "true" ] && [ -n "$KUBECONFIG1_MODIFIED" ] && [ -f "$KUBECONFIG1_MODIFIED" ]; then
        rm -f "$KUBECONFIG1_MODIFIED"
    fi
    if [ -n "$KUBECONFIG1_SANITIZED" ] && [ -f "$KUBECONFIG1_SANITIZED" ]; then
        rm -f "$KUBECONFIG1_SANITIZED"
    fi
    if [ -n "$KUBECONFIG2_SANITIZED" ] && [ -f "$KUBECONFIG2_SANITIZED" ]; then
        rm -f "$KUBECONFIG2_SANITIZED"
    fi
    if [ -n "$TEMP_CONTEXT_TEST_DIR" ] && [ -d "$TEMP_CONTEXT_TEST_DIR" ]; then
        rm -rf "$TEMP_CONTEXT_TEST_DIR"
    fi
}

# Register cleanup on exit (handles both success and failure)
trap cleanup_temp_files EXIT INT TERM

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_DIR="submariner-diagnostics-${TIMESTAMP}"
CLUSTER1_CONTEXT="$1"
KUBECONFIG1="$2"
CLUSTER2_CONTEXT="$3"
KUBECONFIG2="$4"
COMPLAINT="$5"

show_usage() {
    echo "Usage: $0 <cluster1-context> <cluster1-kubeconfig> <cluster2-context> <cluster2-kubeconfig> [issue-description]"
    echo ""
    echo "Arguments:"
    echo "  cluster1-context     - Context name for cluster 1 (required)"
    echo "  cluster1-kubeconfig  - Path to kubeconfig for cluster 1 (required)"
    echo "                         Can be same file as cluster2-kubeconfig if it contains both contexts"
    echo "  cluster2-context     - Context name for cluster 2 (required)"
    echo "  cluster2-kubeconfig  - Path to kubeconfig for cluster 2 (required)"
    echo "                         Can be same file as cluster1-kubeconfig if it contains both contexts"
    echo "  issue-description    - Description of the issue (optional, defaults to 'undefined')"
    echo ""
    echo "Examples:"
    echo "  # Separate kubeconfig files:"
    echo "  $0 cluster1 /path/to/kubeconfig1 cluster2 /path/to/kubeconfig2 'tunnel not connected'"
    echo ""
    echo "  # Single kubeconfig with multiple contexts:"
    echo "  $0 context1 /path/to/kubeconfig context2 /path/to/kubeconfig 'route agent degraded'"
    echo ""
    return 1 2>/dev/null || exit 1
}

# Function to test if context name contains illegal filesystem characters
# Returns 0 if name is safe (no illegal chars), 1 if sanitization needed
can_create_dir_with_name() {
    local test_name="$1"
    local sanitized=$(sanitize_context_name "$test_name")

    # If sanitized name differs from original, illegal characters were found
    if [ "$sanitized" = "$test_name" ]; then
        return 0  # Name is safe
    else
        return 1  # Name contains illegal characters
    fi
}

# Function to sanitize context name by replacing illegal filesystem characters
sanitize_context_name() {
    local context="$1"
    # Replace illegal characters (: / \ @) with dash
    echo "$context" | sed 's/[:/\\@]/-/g'
}

# Function to collect diagnostics from a single cluster
collect_cluster_diagnostics() {
    local cluster_name="$1"
    local kubeconfig="$2"
    local context="$3"
    local cluster_dir="${OUTPUT_DIR}/${cluster_name}"

    echo "=== Collecting from ${cluster_name} (context: ${context}) ==="
    mkdir -p "${cluster_dir}"

    # subctl gather (most comprehensive)
    echo "Running subctl gather for ${cluster_name}..."
    subctl gather --kubeconfig "${kubeconfig}" --context "${context}" --dir "${cluster_dir}/gather" 2>&1 | tee "${cluster_dir}/gather.log"

    # Normalize gather directory structure for analyze-basic.py compatibility
    # subctl gather creates cluster-specific subdirectory, but name may differ from our cluster_name
    # We need to ensure it's named exactly as cluster_name for analyze-basic.py to find summary.html
    ACTUAL_GATHER_SUBDIR=$(find "${cluster_dir}/gather" -mindepth 1 -maxdepth 1 -type d -print -quit 2>/dev/null)
    if [ -n "$ACTUAL_GATHER_SUBDIR" ]; then
        ACTUAL_SUBDIR_NAME=$(basename "$ACTUAL_GATHER_SUBDIR")
        if [ "$ACTUAL_SUBDIR_NAME" != "$cluster_name" ]; then
            # Rename to match expected cluster name
            mv "$ACTUAL_GATHER_SUBDIR" "${cluster_dir}/gather/${cluster_name}" 2>/dev/null || true
        fi
    fi

    # subctl show (connection status)
    echo "Running subctl show for ${cluster_name}..."
    subctl show all --kubeconfig "${kubeconfig}" --context "${context}" > "${cluster_dir}/subctl-show-all.txt" 2>&1

    # subctl diagnose (health checks)
    echo "Running subctl diagnose for ${cluster_name}..."
    subctl diagnose all --kubeconfig "${kubeconfig}" --context "${context}" > "${cluster_dir}/subctl-diagnose-all.txt" 2>&1

    # subctl show versions (version information)
    echo "Running subctl show versions for ${cluster_name}..."
    subctl show versions --kubeconfig "${kubeconfig}" --context "${context}" > "${cluster_dir}/subctl-show-versions.txt" 2>&1

    # Additional CRs that might not be in gather
    echo "Collecting additional CRs for ${cluster_name}..."
    kubectl get routeagents.submariner.io -n submariner-operator -o yaml --kubeconfig "${kubeconfig}" --context "${context}" > "${cluster_dir}/routeagents.yaml" 2>&1 || echo "Failed to get RouteAgents" > "${cluster_dir}/routeagents.yaml"

    # ACM resources (if ACM hub or managed cluster)
    echo "Checking for ACM resources on ${cluster_name}..."
    kubectl get managedclusteraddon -A --kubeconfig "${kubeconfig}" --context "${context}" 2>/dev/null | grep submariner > "${cluster_dir}/acm-addons.txt" || echo "No ACM ManagedClusterAddOn resources found" > "${cluster_dir}/acm-addons.txt"

    # Get SubmarinerConfig but check if there are actual objects (not just empty List)
    SUBMARINERCONFIG_OUTPUT=$(kubectl get submarinerconfig -A -o yaml --kubeconfig "${kubeconfig}" --context "${context}" 2>&1)
    if echo "$SUBMARINERCONFIG_OUTPUT" | grep -q "items:" && echo "$SUBMARINERCONFIG_OUTPUT" | grep -q "kind: SubmarinerConfig"; then
        # Has actual SubmarinerConfig objects
        echo "$SUBMARINERCONFIG_OUTPUT" > "${cluster_dir}/submarinerconfig.yaml"
    else
        # No objects or error
        echo "No SubmarinerConfig resources found" > "${cluster_dir}/submarinerconfig.yaml"
    fi
}

# Function to collect tcpdump from gateway nodes
collect_tcpdump_from_cluster() {
    local cluster_name="$1"
    local kubeconfig="$2"
    local context="$3"
    local tcpdump_dir="$4"
    local capture_duration="${5:-30}"

    echo "=== Collecting tcpdump from ${cluster_name} gateway nodes ==="

    # Get active gateway node from Gateway CR (authoritative source)
    ACTIVE_GATEWAY_HOSTNAME=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.status.gateways[?(@.haStatus=="active")].localEndpoint.hostname}' 2>/dev/null)

    if [ -z "$ACTIVE_GATEWAY_HOSTNAME" ]; then
        echo "  ⚠ No active gateway found in Gateway CR, falling back to first available gateway pod"
        GATEWAY_NODE=$(kubectl get pods -n submariner-operator -l app=submariner-gateway --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null)
    else
        # Find the gateway pod running on the active gateway node
        GATEWAY_NODE=$(kubectl get pods -n submariner-operator -l app=submariner-gateway --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath="{.items[?(@.spec.nodeName==\"${ACTIVE_GATEWAY_HOSTNAME}\")].spec.nodeName}" 2>/dev/null)
        if [ -z "$GATEWAY_NODE" ]; then
            echo "  ⚠ Active gateway node '${ACTIVE_GATEWAY_HOSTNAME}' not found in pod list, using first available"
            GATEWAY_NODE=$(kubectl get pods -n submariner-operator -l app=submariner-gateway --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.items[0].spec.nodeName}' 2>/dev/null)
        else
            echo "  ✓ Using active gateway node: ${GATEWAY_NODE} (from Gateway CR)"
        fi
    fi

    if [ -z "$GATEWAY_NODE" ]; then
        echo "  ✗ No gateway node found in ${cluster_name}, skipping tcpdump"
        return
    fi

    echo "  Gateway node: ${GATEWAY_NODE}"

    # Get Submariner configuration to determine capture filter
    CABLE_DRIVER=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.spec.cableDriver}' 2>/dev/null)
    CABLE_DRIVER=${CABLE_DRIVER:-libreswan}  # Default to libreswan if not set

    # Get USING_IP and PRIVATE_IP from the active gateway (matching ACTIVE_GATEWAY_HOSTNAME)
    # This ensures we capture the correct protocol (ESP vs NAT-T) for the active tunnel
    if [ -n "$ACTIVE_GATEWAY_HOSTNAME" ]; then
        USING_IP=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath="{.status.gateways[?(@.localEndpoint.hostname==\"${ACTIVE_GATEWAY_HOSTNAME}\")].connections[0].usingIP}" 2>/dev/null)
        PRIVATE_IP=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath="{.status.gateways[?(@.localEndpoint.hostname==\"${ACTIVE_GATEWAY_HOSTNAME}\")].connections[0].endpoint.private_ip}" 2>/dev/null)
    fi

    # Fall back to first gateway if active gateway lookup failed
    if [ -z "$USING_IP" ] || [ -z "$PRIVATE_IP" ]; then
        USING_IP=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.status.gateways[0].connections[0].usingIP}' 2>/dev/null)
        PRIVATE_IP=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.status.gateways[0].connections[0].endpoint.private_ip}' 2>/dev/null)
    fi

    FORCE_UDP=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.spec.ceIPSecForceUDPEncaps}' 2>/dev/null)
    NATT_PORT=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.spec.ceIPSecNATTPort}' 2>/dev/null)
    NATT_PORT=${NATT_PORT:-4500}  # Default to 4500 if not set

    # Check if LoadBalancer service is being used
    LB_TYPE=$(kubectl get svc submariner-gateway -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.spec.type}' 2>/dev/null)
    LB_EXTERNAL_TRAFFIC_POLICY=$(kubectl get svc submariner-gateway -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.spec.externalTrafficPolicy}' 2>/dev/null)

    # Get NodePorts if LoadBalancer service is used
    if [ "$LB_TYPE" = "LoadBalancer" ]; then
        NODEPORT_4500=$(kubectl get svc submariner-gateway -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.spec.ports[?(@.port==4500)].nodePort}' 2>/dev/null)
        NODEPORT_4490=$(kubectl get svc submariner-gateway -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.spec.ports[?(@.port==4490)].nodePort}' 2>/dev/null)
        LB_IP=$(kubectl get svc submariner-gateway -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)

        if [ -n "$NODEPORT_4500" ] && [ -n "$NODEPORT_4490" ]; then
            echo "  ✓ LoadBalancer service detected:"
            echo "    LB IP: ${LB_IP:-pending}"
            echo "    NodePorts: ${NODEPORT_4500} (4500), ${NODEPORT_4490} (4490)"
            echo "    External Traffic Policy: ${LB_EXTERNAL_TRAFFIC_POLICY:-Cluster}"
        fi
    fi

    # Determine capture filters based on cable driver and configuration
    # Separate tunnel traffic from ICMP for accurate analysis
    if [ "$CABLE_DRIVER" = "vxlan" ]; then
        CAPTURE_FILTER_TUNNEL="udp port ${NATT_PORT}"
        CAPTURE_FILTER_ICMP="icmp"
        CAPTURE_FILTER="${CAPTURE_FILTER_TUNNEL} or ${CAPTURE_FILTER_ICMP}"
        echo "  Capture filter (tunnel): ${CAPTURE_FILTER_TUNNEL} (VXLAN cable driver)"
        echo "  Capture filter (ICMP): ${CAPTURE_FILTER_ICMP} (health check diagnostics)"
    elif [ "$FORCE_UDP" = "true" ] || [ "$USING_IP" != "$PRIVATE_IP" ]; then
        CAPTURE_FILTER_TUNNEL="udp port ${NATT_PORT}"
        CAPTURE_FILTER_ICMP="icmp"
        CAPTURE_FILTER="${CAPTURE_FILTER_TUNNEL} or ${CAPTURE_FILTER_ICMP}"
        echo "  Capture filter (tunnel): ${CAPTURE_FILTER_TUNNEL} (UDP encapsulation)"
        echo "  Capture filter (ICMP): ${CAPTURE_FILTER_ICMP} (health check diagnostics)"
    else
        CAPTURE_FILTER_TUNNEL="proto 50"
        CAPTURE_FILTER_ICMP="icmp"
        CAPTURE_FILTER="${CAPTURE_FILTER_TUNNEL} or ${CAPTURE_FILTER_ICMP}"
        echo "  Capture filter (tunnel): ${CAPTURE_FILTER_TUNNEL} (ESP protocol)"
        echo "  Capture filter (ICMP): ${CAPTURE_FILTER_ICMP} (health check diagnostics)"
    fi

    # Add LoadBalancer NodePort filters if applicable
    CAPTURE_FILTER_NODEPORTS=""
    if [ "$LB_TYPE" = "LoadBalancer" ] && [ -n "$NODEPORT_4500" ] && [ -n "$NODEPORT_4490" ]; then
        CAPTURE_FILTER_NODEPORTS="udp port ${NODEPORT_4500} or udp port ${NODEPORT_4490}"
        CAPTURE_FILTER="${CAPTURE_FILTER} or ${CAPTURE_FILTER_NODEPORTS}"
        echo "  Capture filter (LoadBalancer NodePorts): ${CAPTURE_FILTER_NODEPORTS}"
        echo "    This captures traffic arriving at NodePorts before OVN forwarding"
    fi

    # Create DaemonSet YAML for tcpdump
    echo "  Applying tcpdump DaemonSet..."
    cat <<EOF | kubectl apply --kubeconfig="${kubeconfig}" --context="${context}" -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: submariner-tcpdump-collector
  namespace: submariner-operator
spec:
  selector:
    matchLabels:
      app: submariner-tcpdump-collector
  template:
    metadata:
      labels:
        app: submariner-tcpdump-collector
    spec:
      nodeSelector:
        submariner.io/gateway: "true"
      tolerations:
      - operator: Exists
      containers:
      - name: tcpdump
        image: quay.io/submariner/nettest:devel
        imagePullPolicy: IfNotPresent
        command:
        - /bin/sh
        - -c
        - |
          echo "Starting tcpdump capture for ${capture_duration} seconds..."
          timeout ${capture_duration} tcpdump -pnni any "${CAPTURE_FILTER}" -w /tmp/gateway-traffic.pcap 2>&1
          echo "Capture complete. Generating analysis..."

          # Generate analysis text file inside the container
          {
            echo "========================================="
            echo "TCPDUMP CAPTURE SUMMARY: ${cluster_name} Gateway"
            echo "Node: ${GATEWAY_NODE}"
            echo "Capture Filter (tunnel): ${CAPTURE_FILTER_TUNNEL}"
            echo "Capture Filter (ICMP): ${CAPTURE_FILTER_ICMP}"
            if [ -n "${CAPTURE_FILTER_NODEPORTS}" ]; then
              echo "Capture Filter (NodePorts): ${CAPTURE_FILTER_NODEPORTS}"
              echo "LoadBalancer Service: Yes (IP: ${LB_IP:-pending})"
              echo "  NodePort mappings: ${NODEPORT_4500} -> 4500, ${NODEPORT_4490} -> 4490"
              echo "  External Traffic Policy: ${LB_EXTERNAL_TRAFFIC_POLICY:-Cluster}"
            fi
            echo "Capture Duration: ${capture_duration} seconds"
            echo "========================================="
            echo ""

            # Count total packets
            TOTAL_PACKETS=\$(tcpdump -r /tmp/gateway-traffic.pcap -nn 2>/dev/null | wc -l)

            # Count tunnel packets only (excluding ICMP)
            TUNNEL_PACKETS=\$(tcpdump -r /tmp/gateway-traffic.pcap -nn "${CAPTURE_FILTER_TUNNEL}" 2>/dev/null | wc -l)

            # Count ICMP packets
            ICMP_PACKETS=\$(tcpdump -r /tmp/gateway-traffic.pcap -nn "${CAPTURE_FILTER_ICMP}" 2>/dev/null | wc -l)

            # Count NodePort packets if LoadBalancer is used
            if [ -n "${CAPTURE_FILTER_NODEPORTS}" ]; then
              NODEPORT_PACKETS=\$(tcpdump -r /tmp/gateway-traffic.pcap -nn "${CAPTURE_FILTER_NODEPORTS}" 2>/dev/null | wc -l)
            else
              NODEPORT_PACKETS=0
            fi

            echo "CAPTURE STATISTICS:"
            echo "  Total packets captured: \${TOTAL_PACKETS}"
            echo "  Tunnel packets (${CAPTURE_FILTER_TUNNEL}): \${TUNNEL_PACKETS}"
            echo "  ICMP packets: \${ICMP_PACKETS}"
            if [ -n "${CAPTURE_FILTER_NODEPORTS}" ]; then
              echo "  NodePort packets (${CAPTURE_FILTER_NODEPORTS}): \${NODEPORT_PACKETS}"
              echo ""
              echo "NODEPORT TRAFFIC ANALYSIS:"
              if [ "\${NODEPORT_PACKETS}" -gt 0 ]; then
                echo "  ✓ Traffic IS arriving on NodePorts (before OVN forwarding)"
                if [ "\${TUNNEL_PACKETS}" -eq 0 ]; then
                  echo "  ⚠ WARNING: NodePort traffic seen, but NO tunnel traffic on ports 4500/4490"
                  echo "     This suggests OVN is NOT forwarding NodePort -> gateway pod ports"
                fi
              else
                echo "  ✗ NO traffic arriving on NodePorts"
                echo "     This suggests LoadBalancer is not sending traffic to this node,"
                echo "     or traffic is blocked before reaching the node."
              fi
            fi
            echo ""

            # Show first 50 packets with details (tunnel traffic only for analysis)
            echo "FIRST 50 TUNNEL PACKETS (detailed):"
            tcpdump -r /tmp/gateway-traffic.pcap -nnv "${CAPTURE_FILTER_TUNNEL}" 2>/dev/null | head -50
            echo ""

            # Show unique source/destination pairs for tunnel traffic
            echo "UNIQUE SOURCE -> DESTINATION PAIRS (tunnel traffic):"
            tcpdump -r /tmp/gateway-traffic.pcap -nnq "${CAPTURE_FILTER_TUNNEL}" 2>/dev/null | sed -n 's/^.* \\([^ ]*\\) > \\([^ :]*\\).*/\\1 -> \\2/p' | sort | uniq -c | sort -rn
            echo ""

            # Optionally show ICMP summary
            if [ "\${ICMP_PACKETS}" -gt 0 ]; then
              echo "ICMP PACKET SUMMARY:"
              tcpdump -r /tmp/gateway-traffic.pcap -nnq "${CAPTURE_FILTER_ICMP}" 2>/dev/null | head -20
              echo ""
            fi

            # Show NodePort traffic details if LoadBalancer is used
            if [ -n "${CAPTURE_FILTER_NODEPORTS}" ] && [ "\${NODEPORT_PACKETS}" -gt 0 ]; then
              echo "NODEPORT TRAFFIC DETAILS (first 30 packets):"
              tcpdump -r /tmp/gateway-traffic.pcap -nnv "${CAPTURE_FILTER_NODEPORTS}" 2>/dev/null | head -30
              echo ""

              echo "NODEPORT SOURCE IPs (shows where traffic is coming from):"
              tcpdump -r /tmp/gateway-traffic.pcap -nnq "${CAPTURE_FILTER_NODEPORTS}" 2>/dev/null | \
                sed -n 's/^.* \\([^ ]*\\) > \\([^ :]*\\).*/\\1/p' | sort | uniq -c | sort -rn | head -10
              echo ""

              echo "NODEPORT DESTINATION IPs (shows which node IPs receive traffic):"
              tcpdump -r /tmp/gateway-traffic.pcap -nnq "${CAPTURE_FILTER_NODEPORTS}" 2>/dev/null | \
                sed -n 's/^.* \\([^ ]*\\) > \\([^ :]*\\).*/\\2/p' | sort | uniq -c | sort -rn | head -10
              echo ""
            fi

          } > /tmp/gateway-analysis.txt 2>&1

          echo "Analysis complete. Waiting for file extraction..."
          sleep 300
        securityContext:
          privileged: true
          capabilities:
            add:
            - NET_ADMIN
            - NET_RAW
        volumeMounts:
        - name: host-tmp
          mountPath: /tmp
      volumes:
      - name: host-tmp
        emptyDir: {}
      restartPolicy: Always
      hostNetwork: true
      serviceAccount: submariner-routeagent
      serviceAccountName: submariner-routeagent
EOF

    if [ $? -ne 0 ]; then
        echo "  ✗ Failed to deploy tcpdump DaemonSet on ${cluster_name}"
        # Attempt cleanup in case DaemonSet was partially created
        kubectl delete daemonset submariner-tcpdump-collector -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" >/dev/null 2>&1
        return
    fi

    echo "  ✓ tcpdump DaemonSet deployed on ${cluster_name}"
    echo "  Waiting for pod to start..."
    sleep 5

    # Wait for pod to be ready
    if ! kubectl wait --for=condition=Ready pod -l app=submariner-tcpdump-collector -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" --timeout=30s 2>&1; then
        echo "  ⚠ Warning: Pod did not become ready within 30s, will attempt to continue..."
    fi

    # Get the tcpdump pod running on the selected gateway node
    TCPDUMP_POD=$(kubectl get pods -n submariner-operator -l app=submariner-tcpdump-collector --kubeconfig="${kubeconfig}" --context="${context}" -o jsonpath="{.items[?(@.spec.nodeName==\"${GATEWAY_NODE}\")].metadata.name}" 2>/dev/null)

    if [ -z "$TCPDUMP_POD" ]; then
        echo "  ✗ tcpdump pod not found on node ${GATEWAY_NODE} in ${cluster_name}"
        kubectl delete daemonset submariner-tcpdump-collector -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" >/dev/null 2>&1
        return
    fi

    echo "  tcpdump pod: ${TCPDUMP_POD}"
    echo "  Capturing traffic for ${capture_duration} seconds..."

    # Wait for capture to complete
    sleep $((capture_duration + 5))

    # Extract pcap file (using kubectl exec instead of cp since nettest image doesn't have tar)
    echo "  Extracting files from ${cluster_name}..."
    kubectl exec -n submariner-operator "${TCPDUMP_POD}" --kubeconfig="${kubeconfig}" --context="${context}" -- cat /tmp/gateway-traffic.pcap > "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}.pcap"

    # Extract analysis file
    kubectl exec -n submariner-operator "${TCPDUMP_POD}" --kubeconfig="${kubeconfig}" --context="${context}" -- cat /tmp/gateway-analysis.txt > "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}-analysis.txt"

    # Check if files were extracted successfully
    if [ -f "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}.pcap" ]; then
        PCAP_SIZE=$(stat -f%z "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}.pcap" 2>/dev/null || stat -c%s "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}.pcap" 2>/dev/null)
        if [ "$PCAP_SIZE" -gt 100 ]; then
            echo "  ✓ pcap file collected: ${cluster_name}-gateway-${GATEWAY_NODE}.pcap (${PCAP_SIZE} bytes)"

            if [ -f "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}-analysis.txt" ]; then
                echo "  ✓ Analysis file collected: ${cluster_name}-gateway-${GATEWAY_NODE}-analysis.txt"
            else
                echo "  ⚠ Analysis file not found (will be generated from pcap if needed)"
            fi
        else
            echo "  ✗ pcap file is empty or too small (${PCAP_SIZE} bytes) - no traffic captured"

            # Keep the analysis file even if pcap is empty (it will show 0 packets)
            if [ -f "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}-analysis.txt" ]; then
                echo "  ✓ Analysis file collected (shows no traffic)"
            fi

            # Remove empty pcap file
            rm -f "${tcpdump_dir}/${cluster_name}-gateway-${GATEWAY_NODE}.pcap"
        fi
    else
        echo "  ✗ Failed to extract files from ${cluster_name}"
    fi

    # Cleanup
    echo "  Cleaning up tcpdump DaemonSet from ${cluster_name}..."
    kubectl delete daemonset submariner-tcpdump-collector -n submariner-operator --kubeconfig="${kubeconfig}" --context="${context}" >/dev/null 2>&1
    echo "  ✓ Cleanup complete"
}

# Function to collect firewall inter-cluster diagnostics
collect_firewall_inter_cluster() {
    local cluster1_name="$1"
    local kubeconfig1="$2"
    local cluster2_name="$3"
    local kubeconfig2="$4"
    local firewall_dir="$5"
    local image_override="$6"

    echo "=== Collecting firewall inter-cluster diagnostics ==="
    echo "  This tests firewall requirements for inter-cluster traffic"

    # Merge kubeconfigs temporarily for subctl diagnose firewall
    MERGED_KUBECONFIG_FW="${firewall_dir}/merged-kubeconfig-fw"
    KUBECONFIG="${kubeconfig1}:${kubeconfig2}" kubectl config view --flatten > "${MERGED_KUBECONFIG_FW}"

    # Build command
    FIREWALL_CMD="KUBECONFIG=${MERGED_KUBECONFIG_FW} subctl diagnose firewall inter-cluster --context ${cluster1_name} --remotecontext ${cluster2_name} --verbose"
    if [ -n "$image_override" ]; then
        FIREWALL_CMD="${FIREWALL_CMD} ${image_override}"
    fi

    echo "========================================" > "${firewall_dir}/firewall-inter-cluster.txt"
    echo "Command executed:" >> "${firewall_dir}/firewall-inter-cluster.txt"
    echo "${FIREWALL_CMD}" >> "${firewall_dir}/firewall-inter-cluster.txt"
    echo "========================================" >> "${firewall_dir}/firewall-inter-cluster.txt"
    echo "" >> "${firewall_dir}/firewall-inter-cluster.txt"
    echo "CONTEXT: This test was run because:" >> "${firewall_dir}/firewall-inter-cluster.txt"
    echo "  - Tunnel not connected on one or both clusters" >> "${firewall_dir}/firewall-inter-cluster.txt"
    echo "  - Inter-cluster traffic uses UDP encapsulation (VxLAN or IPSec with NAT-T)" >> "${firewall_dir}/firewall-inter-cluster.txt"
    echo "  - Testing if firewall rules are blocking inter-cluster traffic" >> "${firewall_dir}/firewall-inter-cluster.txt"
    echo "" >> "${firewall_dir}/firewall-inter-cluster.txt"

    echo "  Running firewall inter-cluster test..."
    echo "  Start time: $(date '+%Y-%m-%d %H:%M:%S')"

    # Run firewall test
    KUBECONFIG="${MERGED_KUBECONFIG_FW}" subctl diagnose firewall inter-cluster \
        --context "${cluster1_name}" \
        --remotecontext "${cluster2_name}" \
        --verbose \
        ${image_override} \
        >> "${firewall_dir}/firewall-inter-cluster.txt" 2>&1

    FW_EXIT_CODE=$?
    echo "  End time: $(date '+%Y-%m-%d %H:%M:%S')"

    if [ $FW_EXIT_CODE -eq 0 ]; then
        echo "  ✓ Firewall inter-cluster test completed successfully"
    else
        echo "  ⚠ Firewall inter-cluster test completed with errors (exit code: $FW_EXIT_CODE)"
        echo "     Check firewall-inter-cluster.txt for details"
    fi

    # Cleanup merged kubeconfig
    rm -f "${MERGED_KUBECONFIG_FW}"
}

# Function to collect firewall intra-cluster diagnostics
collect_firewall_intra_cluster() {
    local cluster_name="$1"
    local kubeconfig="$2"
    local context="$3"
    local firewall_dir="$4"
    local image_override="$5"

    echo "=== Collecting firewall intra-cluster diagnostics for ${cluster_name} ==="
    echo "  This tests firewall requirements for intra-cluster Submariner traffic"

    # Build command
    FIREWALL_CMD="subctl diagnose firewall intra-cluster --kubeconfig ${kubeconfig} --context ${context} --verbose"
    if [ -n "$image_override" ]; then
        FIREWALL_CMD="${FIREWALL_CMD} ${image_override}"
    fi

    echo "========================================" > "${firewall_dir}/firewall-intra-cluster-${cluster_name}.txt"
    echo "Command executed:" >> "${firewall_dir}/firewall-intra-cluster-${cluster_name}.txt"
    echo "${FIREWALL_CMD}" >> "${firewall_dir}/firewall-intra-cluster-${cluster_name}.txt"
    echo "========================================" >> "${firewall_dir}/firewall-intra-cluster-${cluster_name}.txt"
    echo "" >> "${firewall_dir}/firewall-intra-cluster-${cluster_name}.txt"
    echo "CONTEXT: This test was run because:" >> "${firewall_dir}/firewall-intra-cluster-${cluster_name}.txt"
    echo "  - CNI is not OVN-Kubernetes (intra-cluster firewall requirements apply)" >> "${firewall_dir}/firewall-intra-cluster-${cluster_name}.txt"
    echo "  - Testing if firewall rules are blocking intra-cluster Submariner traffic" >> "${firewall_dir}/firewall-intra-cluster-${cluster_name}.txt"
    echo "" >> "${firewall_dir}/firewall-intra-cluster-${cluster_name}.txt"

    echo "  Running firewall intra-cluster test for ${cluster_name}..."
    echo "  Start time: $(date '+%Y-%m-%d %H:%M:%S')"

    # Run firewall test
    subctl diagnose firewall intra-cluster \
        --kubeconfig "${kubeconfig}" \
        --context "${context}" \
        --verbose \
        ${image_override} \
        >> "${firewall_dir}/firewall-intra-cluster-${cluster_name}.txt" 2>&1

    FW_EXIT_CODE=$?
    echo "  End time: $(date '+%Y-%m-%d %H:%M:%S')"

    if [ $FW_EXIT_CODE -eq 0 ]; then
        echo "  ✓ Firewall intra-cluster test for ${cluster_name} completed successfully"
    else
        echo "  ⚠ Firewall intra-cluster test for ${cluster_name} completed with errors (exit code: $FW_EXIT_CODE)"
        echo "     Check firewall-intra-cluster-${cluster_name}.txt for details"
    fi
}

# Function to check and compare subctl and Submariner versions
check_version_compatibility() {
    local kubeconfig="$1"
    local context="$2"
    local cluster_name="$3"

    # Get Submariner version from cluster
    local submariner_version=$(subctl show versions --kubeconfig="${kubeconfig}" --context="${context}" 2>/dev/null | grep -E 'submariner-gateway|submariner-operator' | awk '{print $3}' | head -1 | grep -oP 'release-\K[0-9]+\.[0-9]+' | head -1)

    if [ -z "$submariner_version" ]; then
        echo "  ${cluster_name}: ⚠ Unable to detect Submariner version"
        return 1
    fi

    echo "  ${cluster_name}: Submariner version: release-${submariner_version}"

    # Store version for this cluster
    if [ "$cluster_name" = "cluster1" ]; then
        SUBMARINER_VER_C1="$submariner_version"
    else
        SUBMARINER_VER_C2="$submariner_version"
    fi

    # Compare with subctl version
    if [ "$SUBCTL_VERSION_MAJOR_MINOR" != "$submariner_version" ]; then
        echo "  ${cluster_name}: ⚠ VERSION MISMATCH!"
        echo "    subctl version:      v${SUBCTL_VERSION_MAJOR_MINOR}"
        echo "    Submariner version:  release-${submariner_version}"
        return 1
    else
        echo "  ${cluster_name}: ✓ Versions compatible (v${SUBCTL_VERSION_MAJOR_MINOR})"
        return 0
    fi
}

# Check if at least 4 parameters are provided (issue-description is optional)
if [ $# -lt 4 ]; then
    echo "ERROR: At least 4 parameters are required (issue-description is optional)"
    echo ""
    show_usage
    return 1 2>/dev/null || exit 1
fi

# Set issue-description to "undefined" if not provided
if [ $# -eq 4 ]; then
    echo "Note: Issue description not provided - using 'undefined'"
    COMPLAINT="undefined"
fi

# Validate parameters before starting collection
echo "Validating parameters..."

# Validate kubeconfig1 exists
if [ ! -f "$KUBECONFIG1" ]; then
    echo "ERROR: Kubeconfig file not found: $KUBECONFIG1"
    return 1 2>/dev/null || exit 1
fi

# Validate kubeconfig2 exists
if [ ! -f "$KUBECONFIG2" ]; then
    echo "ERROR: Kubeconfig file not found: $KUBECONFIG2"
    return 1 2>/dev/null || exit 1
fi

# Validate context1 exists in kubeconfig1
echo "Checking context in cluster1 kubeconfig..."
if ! kubectl config get-contexts "$CLUSTER1_CONTEXT" --kubeconfig "$KUBECONFIG1" &>/dev/null; then
    echo "ERROR: Context '$CLUSTER1_CONTEXT' not found in kubeconfig: $KUBECONFIG1"
    echo "Available contexts:"
    kubectl config get-contexts --kubeconfig "$KUBECONFIG1" -o name
    return 1 2>/dev/null || exit 1
fi

# Validate cluster1 connectivity
echo "Checking connectivity to cluster1..."
if ! kubectl cluster-info --kubeconfig "$KUBECONFIG1" --context "$CLUSTER1_CONTEXT" &>/dev/null; then
    echo "ERROR: Cannot connect to cluster using kubeconfig: $KUBECONFIG1, context: $CLUSTER1_CONTEXT"
    echo "Please verify:"
    echo "  - The kubeconfig file is valid"
    echo "  - The context exists and is properly configured"
    echo "  - The cluster is accessible from this machine"
    echo "  - Your credentials are valid"
    return 1 2>/dev/null || exit 1
fi

# Validate context2 exists in kubeconfig2
echo "Checking context in cluster2 kubeconfig..."
if ! kubectl config get-contexts "$CLUSTER2_CONTEXT" --kubeconfig "$KUBECONFIG2" &>/dev/null; then
    echo "ERROR: Context '$CLUSTER2_CONTEXT' not found in kubeconfig: $KUBECONFIG2"
    echo "Available contexts:"
    kubectl config get-contexts --kubeconfig "$KUBECONFIG2" -o name
    return 1 2>/dev/null || exit 1
fi

# Validate cluster2 connectivity
echo "Checking connectivity to cluster2..."
if ! kubectl cluster-info --kubeconfig "$KUBECONFIG2" --context "$CLUSTER2_CONTEXT" &>/dev/null; then
    echo "ERROR: Cannot connect to cluster using kubeconfig: $KUBECONFIG2, context: $CLUSTER2_CONTEXT"
    echo "Please verify:"
    echo "  - The kubeconfig file is valid"
    echo "  - The context exists and is properly configured"
    echo "  - The cluster is accessible from this machine"
    echo "  - Your credentials are valid"
    return 1 2>/dev/null || exit 1
fi

# Check for overlapping context names
CONTEXT_RENAMED=false
ORIGINAL_CLUSTER1_CONTEXT="$CLUSTER1_CONTEXT"
KUBECONFIG1_MODIFIED=""

if [ "$CLUSTER1_CONTEXT" = "$CLUSTER2_CONTEXT" ]; then
    echo "WARNING: Both clusters use the same context name: '$CLUSTER1_CONTEXT'"
    echo "  This will cause 'subctl verify' to fail (it requires unique context names)"
    echo ""
    echo "Auto-fixing: Creating a copy of cluster1 kubeconfig with renamed context..."
    echo ""

    # Create a temporary modified kubeconfig for cluster1
    KUBECONFIG1_MODIFIED="${KUBECONFIG1}.submariner-renamed-context"
    cp "$KUBECONFIG1" "$KUBECONFIG1_MODIFIED"

    # Generate new unique context name
    NEW_CLUSTER1_CONTEXT="${CLUSTER1_CONTEXT}-cluster1"

    # Rename context in the copy using kubectl
    # This renames: context name, cluster reference, and user reference
    KUBECONFIG="$KUBECONFIG1_MODIFIED" kubectl config rename-context "$CLUSTER1_CONTEXT" "$NEW_CLUSTER1_CONTEXT" >/dev/null 2>&1

    if [ $? -eq 0 ]; then
        echo "  ✓ Created modified kubeconfig: $KUBECONFIG1_MODIFIED"
        echo "  ✓ Renamed context: '$CLUSTER1_CONTEXT' → '$NEW_CLUSTER1_CONTEXT'"
        echo "  ✓ Original kubeconfig preserved: $KUBECONFIG1"
        echo ""

        # Update cluster1 context to use the renamed one
        CLUSTER1_CONTEXT="$NEW_CLUSTER1_CONTEXT"
        KUBECONFIG1="$KUBECONFIG1_MODIFIED"
        CONTEXT_RENAMED=true

        echo "Proceeding with renamed context for cluster1..."
        echo "  cluster1 context: $CLUSTER1_CONTEXT (renamed)"
        echo "  cluster2 context: $CLUSTER2_CONTEXT (original)"
        echo ""
    else
        echo "ERROR: Failed to rename context in kubeconfig copy"
        echo "Please manually rename the context in one of your kubeconfig files."
        echo ""
        echo "Example manual fix:"
        echo "  # Backup your kubeconfig"
        echo "  cp $KUBECONFIG1 ${KUBECONFIG1}.backup"
        echo ""
        echo "  # Rename context"
        echo "  kubectl config rename-context $CLUSTER1_CONTEXT cluster1 --kubeconfig=$KUBECONFIG1"
        echo ""
        echo "  # Then re-run this script with the renamed context name"
        return 1 2>/dev/null || exit 1
    fi
fi

# Create temporary directory for testing context names
TEMP_CONTEXT_TEST_DIR=$(mktemp -d -t submariner-context-test.XXXXXX)

# Test if context names can be used as directory names
ORIGINAL_CLUSTER1_CONTEXT_SANITIZE="$CLUSTER1_CONTEXT"
ORIGINAL_CLUSTER2_CONTEXT_SANITIZE="$CLUSTER2_CONTEXT"

# Test cluster1 context
echo "Validating cluster1 context name for filesystem compatibility..."
if ! can_create_dir_with_name "$CLUSTER1_CONTEXT"; then
    echo ""
    echo "========================================"
    echo "⚠ WARNING: ILLEGAL CHARACTERS DETECTED"
    echo "========================================"
    echo ""
    echo "Cluster1 context name contains characters that cannot be used in directory names:"
    echo "  Context: '$CLUSTER1_CONTEXT'"
    echo ""
    echo "The 'subctl gather' command will fail to create directories with this context name."
    echo ""
    echo "Auto-fixing: Creating a temporary sanitized kubeconfig copy..."
    echo ""

    # Create sanitized kubeconfig
    KUBECONFIG1_SANITIZED="${KUBECONFIG1}.submariner-sanitized"
    cp "$KUBECONFIG1" "$KUBECONFIG1_SANITIZED"

    # Generate sanitized context name
    SANITIZED_CLUSTER1_CONTEXT=$(sanitize_context_name "$CLUSTER1_CONTEXT")

    # Rename context
    KUBECONFIG="$KUBECONFIG1_SANITIZED" kubectl config rename-context "$CLUSTER1_CONTEXT" "$SANITIZED_CLUSTER1_CONTEXT" >/dev/null 2>&1

    if [ $? -eq 0 ]; then
        echo "  ✓ Created sanitized kubeconfig: $KUBECONFIG1_SANITIZED"
        echo "  ✓ Sanitized context name: '$CLUSTER1_CONTEXT' → '$SANITIZED_CLUSTER1_CONTEXT'"
        echo "  ✓ Original kubeconfig preserved: $KUBECONFIG1"
        echo ""
        echo "Proceeding with sanitized context name for cluster1..."
        CLUSTER1_CONTEXT="$SANITIZED_CLUSTER1_CONTEXT"
        KUBECONFIG1="$KUBECONFIG1_SANITIZED"
        echo ""
    else
        echo "ERROR: Failed to create sanitized kubeconfig"
        return 1 2>/dev/null || exit 1
    fi
else
    echo "  ✓ Context name is filesystem-safe"
fi

# Test cluster2 context
echo "Validating cluster2 context name for filesystem compatibility..."
if ! can_create_dir_with_name "$CLUSTER2_CONTEXT"; then
    echo ""
    echo "========================================"
    echo "⚠ WARNING: ILLEGAL CHARACTERS DETECTED"
    echo "========================================"
    echo ""
    echo "Cluster2 context name contains characters that cannot be used in directory names:"
    echo "  Context: '$CLUSTER2_CONTEXT'"
    echo ""
    echo "The 'subctl gather' command will fail to create directories with this context name."
    echo ""
    echo "Auto-fixing: Creating a temporary sanitized kubeconfig copy..."
    echo ""

    # Create sanitized kubeconfig
    KUBECONFIG2_SANITIZED="${KUBECONFIG2}.submariner-sanitized"
    cp "$KUBECONFIG2" "$KUBECONFIG2_SANITIZED"

    # Generate sanitized context name
    SANITIZED_CLUSTER2_CONTEXT=$(sanitize_context_name "$CLUSTER2_CONTEXT")

    # Rename context
    KUBECONFIG="$KUBECONFIG2_SANITIZED" kubectl config rename-context "$CLUSTER2_CONTEXT" "$SANITIZED_CLUSTER2_CONTEXT" >/dev/null 2>&1

    if [ $? -eq 0 ]; then
        echo "  ✓ Created sanitized kubeconfig: $KUBECONFIG2_SANITIZED"
        echo "  ✓ Sanitized context name: '$CLUSTER2_CONTEXT' → '$SANITIZED_CLUSTER2_CONTEXT'"
        echo "  ✓ Original kubeconfig preserved: $KUBECONFIG2"
        echo ""
        echo "Proceeding with sanitized context name for cluster2..."
        CLUSTER2_CONTEXT="$SANITIZED_CLUSTER2_CONTEXT"
        KUBECONFIG2="$KUBECONFIG2_SANITIZED"
        echo ""
    else
        echo "ERROR: Failed to create sanitized kubeconfig"
        return 1 2>/dev/null || exit 1
    fi
else
    echo "  ✓ Context name is filesystem-safe"
fi

# Check for required tools
echo "Checking for required tools..."
if ! command -v subctl &>/dev/null; then
    echo "ERROR: 'subctl' command not found"
    echo "Please install subctl from: https://github.com/submariner-io/subctl"
    return 1 2>/dev/null || exit 1
fi

if ! command -v kubectl &>/dev/null; then
    echo "ERROR: 'kubectl' command not found"
    echo "Please install kubectl"
    return 1 2>/dev/null || exit 1
fi

echo "✓ All validations passed"
echo ""

# Check if Submariner is deployed on both clusters
echo "Checking if Submariner is deployed on both clusters..."

# Check cluster1
if kubectl get deployment submariner-operator -n submariner-operator --kubeconfig="${KUBECONFIG1}" --context="${CLUSTER1_CONTEXT}" >/dev/null 2>&1; then
    SUBMARINER_DEPLOYED_C1="1"
else
    SUBMARINER_DEPLOYED_C1="0"
fi

# Check cluster2
if kubectl get deployment submariner-operator -n submariner-operator --kubeconfig="${KUBECONFIG2}" --context="${CLUSTER2_CONTEXT}" >/dev/null 2>&1; then
    SUBMARINER_DEPLOYED_C2="1"
else
    SUBMARINER_DEPLOYED_C2="0"
fi

SUBMARINER_NOT_DEPLOYED=false

if [ "$SUBMARINER_DEPLOYED_C1" = "0" ]; then
    echo "  ✗ Cluster1: Submariner operator not found in 'submariner-operator' namespace"
    SUBMARINER_NOT_DEPLOYED=true
else
    echo "  ✓ Cluster1: Submariner operator found"
fi

if [ "$SUBMARINER_DEPLOYED_C2" = "0" ]; then
    echo "  ✗ Cluster2: Submariner operator not found in 'submariner-operator' namespace"
    SUBMARINER_NOT_DEPLOYED=true
else
    echo "  ✓ Cluster2: Submariner operator found"
fi

if [ "$SUBMARINER_NOT_DEPLOYED" = "true" ]; then
    echo ""
    echo "========================================"
    echo "ERROR: Submariner not deployed"
    echo "========================================"
    echo ""
    echo "This tool collects diagnostics from existing Submariner deployments."
    echo "Submariner must be deployed on BOTH clusters before running diagnostics."
    echo ""
    echo "To deploy Submariner, see:"
    echo "  https://submariner.io/getting-started/"
    echo ""
    echo "If Submariner is deployed in a different namespace, please check:"
    echo "  kubectl get deployments -A | grep submariner"
    echo ""
    return 1 2>/dev/null || exit 1
fi

echo ""

# Check subctl and Submariner version compatibility
echo "Checking version compatibility..."

# Get subctl version
SUBCTL_VERSION_FULL=$(subctl version 2>/dev/null | grep -oP 'subctl version: v\K[0-9]+\.[0-9]+\.[0-9]+')
SUBCTL_VERSION_MAJOR_MINOR=$(echo "$SUBCTL_VERSION_FULL" | grep -oP '[0-9]+\.[0-9]+')

if [ -z "$SUBCTL_VERSION_MAJOR_MINOR" ]; then
    echo "⚠ WARNING: Unable to detect subctl version"
    SUBCTL_VERSION_FULL="unknown"
    SUBCTL_VERSION_MAJOR_MINOR="unknown"
else
    echo "subctl version: v${SUBCTL_VERSION_FULL}"
fi

# Initialize version variables
SUBMARINER_VER_C1=""
SUBMARINER_VER_C2=""
VERSION_MISMATCH_C1=false
VERSION_MISMATCH_C2=false

# Check cluster1
if [ "$SUBCTL_VERSION_MAJOR_MINOR" != "unknown" ]; then
    if ! check_version_compatibility "${KUBECONFIG1}" "${CLUSTER1_CONTEXT}" "cluster1"; then
        VERSION_MISMATCH_C1=true
    fi
fi

# Check cluster2
if [ "$SUBCTL_VERSION_MAJOR_MINOR" != "unknown" ]; then
    if ! check_version_compatibility "${KUBECONFIG2}" "${CLUSTER2_CONTEXT}" "cluster2"; then
        VERSION_MISMATCH_C2=true
    fi
fi

# Check if clusters have different Submariner versions
if [ -n "$SUBMARINER_VER_C1" ] && [ -n "$SUBMARINER_VER_C2" ] && [ "$SUBMARINER_VER_C1" != "$SUBMARINER_VER_C2" ]; then
    echo ""
    echo "⚠ WARNING: Different Submariner versions detected between clusters!"
    echo "  Cluster1: release-${SUBMARINER_VER_C1}"
    echo "  Cluster2: release-${SUBMARINER_VER_C2}"
    echo "  This is NOT recommended and may cause compatibility issues."
fi

# Display warning if version mismatch detected
if [ "$VERSION_MISMATCH_C1" = "true" ] || [ "$VERSION_MISMATCH_C2" = "true" ]; then
    echo ""
    echo "========================================"
    echo "⚠ WARNING: VERSION MISMATCH DETECTED!"
    echo "========================================"
    echo ""
    echo "subctl and Submariner versions should match for compatibility."
    echo ""
    if [ "$VERSION_MISMATCH_C1" = "true" ]; then
        echo "Cluster1 mismatch:"
        echo "  subctl:      v${SUBCTL_VERSION_MAJOR_MINOR}"
        echo "  Submariner:  release-${SUBMARINER_VER_C1}"
        echo ""
    fi
    if [ "$VERSION_MISMATCH_C2" = "true" ]; then
        echo "Cluster2 mismatch:"
        echo "  subctl:      v${SUBCTL_VERSION_MAJOR_MINOR}"
        echo "  Submariner:  release-${SUBMARINER_VER_C2}"
        echo ""
    fi
    echo "Recommended action:"
    if [ -n "$SUBMARINER_VER_C1" ]; then
        echo "  Update subctl to version v${SUBMARINER_VER_C1}"
    elif [ -n "$SUBMARINER_VER_C2" ]; then
        echo "  Update subctl to version v${SUBMARINER_VER_C2}"
    fi
    echo ""
    echo "Note: Collection will continue automatically despite version mismatch."
    echo "      This warning has been logged to manifest.txt for reference."
    echo ""
    echo ""
fi

echo ""

mkdir -p "${OUTPUT_DIR}"

# Set up collection logging - capture all output to both console and log file
COLLECTION_LOG="${OUTPUT_DIR}/collection.log"
exec > >(tee -a "${COLLECTION_LOG}") 2>&1

COLLECTION_START_TIME=$(date +%s)
echo "========================================="
echo "Collecting Submariner diagnostics..."
echo "Start time: $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================="
echo ""
echo "Timestamp: ${TIMESTAMP}" > "${OUTPUT_DIR}/manifest.txt"
echo "Complaint: ${COMPLAINT}" >> "${OUTPUT_DIR}/manifest.txt"
echo "" >> "${OUTPUT_DIR}/manifest.txt"
echo "Collection Log: See collection.log for detailed output and any errors" >> "${OUTPUT_DIR}/manifest.txt"
echo "" >> "${OUTPUT_DIR}/manifest.txt"

# Document context renaming if it occurred
if [ "$CONTEXT_RENAMED" = "true" ]; then
    echo "Context Name Handling:" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  ⚠ Overlapping context names detected and auto-fixed" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Original cluster1 context: ${ORIGINAL_CLUSTER1_CONTEXT}" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Original cluster2 context: ${CLUSTER2_CONTEXT}" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Renamed cluster1 context: ${CLUSTER1_CONTEXT}" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Action: Created temporary kubeconfig copy with renamed context" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Note: This was required because subctl verify needs unique context names" >> "${OUTPUT_DIR}/manifest.txt"
    echo "" >> "${OUTPUT_DIR}/manifest.txt"
fi

# Document context sanitization if it occurred
if [ "$ORIGINAL_CLUSTER1_CONTEXT_SANITIZE" != "$CLUSTER1_CONTEXT" ] || [ "$ORIGINAL_CLUSTER2_CONTEXT_SANITIZE" != "$CLUSTER2_CONTEXT" ]; then
    echo "Context Name Sanitization:" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  ⚠ Context names contained illegal filesystem characters and were auto-fixed" >> "${OUTPUT_DIR}/manifest.txt"

    if [ "$ORIGINAL_CLUSTER1_CONTEXT_SANITIZE" != "$CLUSTER1_CONTEXT" ]; then
        echo "  Original cluster1 context: ${ORIGINAL_CLUSTER1_CONTEXT_SANITIZE}" >> "${OUTPUT_DIR}/manifest.txt"
        echo "  Sanitized cluster1 context: ${CLUSTER1_CONTEXT}" >> "${OUTPUT_DIR}/manifest.txt"
    fi

    if [ "$ORIGINAL_CLUSTER2_CONTEXT_SANITIZE" != "$CLUSTER2_CONTEXT" ]; then
        echo "  Original cluster2 context: ${ORIGINAL_CLUSTER2_CONTEXT_SANITIZE}" >> "${OUTPUT_DIR}/manifest.txt"
        echo "  Sanitized cluster2 context: ${CLUSTER2_CONTEXT}" >> "${OUTPUT_DIR}/manifest.txt"
    fi

    echo "  Note: Characters like ':', '/', '\\', '@' cannot be used in directory names" >> "${OUTPUT_DIR}/manifest.txt"
    echo "" >> "${OUTPUT_DIR}/manifest.txt"
fi

# Add version information to manifest
echo "Version Information:" >> "${OUTPUT_DIR}/manifest.txt"
echo "  subctl version: v${SUBCTL_VERSION_FULL}" >> "${OUTPUT_DIR}/manifest.txt"
if [ -n "$SUBMARINER_VER_C1" ]; then
    echo "  Cluster1 Submariner version: release-${SUBMARINER_VER_C1}" >> "${OUTPUT_DIR}/manifest.txt"
fi
if [ -n "$SUBMARINER_VER_C2" ]; then
    echo "  Cluster2 Submariner version: release-${SUBMARINER_VER_C2}" >> "${OUTPUT_DIR}/manifest.txt"
fi

# Document version mismatch warnings if any
if [ "$VERSION_MISMATCH_C1" = "true" ] || [ "$VERSION_MISMATCH_C2" = "true" ]; then
    echo "  ⚠ VERSION MISMATCH DETECTED!" >> "${OUTPUT_DIR}/manifest.txt"
    if [ "$VERSION_MISMATCH_C1" = "true" ]; then
        echo "    Cluster1: subctl v${SUBCTL_VERSION_MAJOR_MINOR} vs Submariner release-${SUBMARINER_VER_C1}" >> "${OUTPUT_DIR}/manifest.txt"
    fi
    if [ "$VERSION_MISMATCH_C2" = "true" ]; then
        echo "    Cluster2: subctl v${SUBCTL_VERSION_MAJOR_MINOR} vs Submariner release-${SUBMARINER_VER_C2}" >> "${OUTPUT_DIR}/manifest.txt"
    fi
fi

# Document if clusters have different Submariner versions
if [ -n "$SUBMARINER_VER_C1" ] && [ -n "$SUBMARINER_VER_C2" ] && [ "$SUBMARINER_VER_C1" != "$SUBMARINER_VER_C2" ]; then
    echo "  ⚠ Different Submariner versions between clusters (NOT recommended)" >> "${OUTPUT_DIR}/manifest.txt"
fi
echo "" >> "${OUTPUT_DIR}/manifest.txt"

# Collect from Cluster 1
echo "Cluster 1:" >> "${OUTPUT_DIR}/manifest.txt"
echo "  Context: ${CLUSTER1_CONTEXT}" >> "${OUTPUT_DIR}/manifest.txt"
echo "  Kubeconfig: ${KUBECONFIG1##*/}" >> "${OUTPUT_DIR}/manifest.txt"
echo "" >> "${OUTPUT_DIR}/manifest.txt"

collect_cluster_diagnostics "cluster1" "${KUBECONFIG1}" "${CLUSTER1_CONTEXT}"

# Collect from Cluster 2
echo "Cluster 2:" >> "${OUTPUT_DIR}/manifest.txt"
echo "  Context: ${CLUSTER2_CONTEXT}" >> "${OUTPUT_DIR}/manifest.txt"
echo "  Kubeconfig: ${KUBECONFIG2##*/}" >> "${OUTPUT_DIR}/manifest.txt"
echo "" >> "${OUTPUT_DIR}/manifest.txt"

collect_cluster_diagnostics "cluster2" "${KUBECONFIG2}" "${CLUSTER2_CONTEXT}"

# Check for nettest image pull failures in subctl diagnose output
echo ""
echo "=== Checking for image pull issues ==="
NETTEST_IMAGE_FAILED=false
NETTEST_IMAGE_C1=""
NETTEST_IMAGE_C2=""

# Extract the actual image being used from error messages
if grep -q "ImagePullBackOff.*nettest\|ErrImagePull.*nettest\|unauthorized.*nettest" "${OUTPUT_DIR}/cluster1/subctl-diagnose-all.txt" 2>/dev/null; then
    NETTEST_IMAGE_C1=$(grep -oE '(registry[^"[:space:]]*nettest[^"[:space:]]*)' "${OUTPUT_DIR}/cluster1/subctl-diagnose-all.txt" 2>/dev/null | head -1)
    echo "⚠ WARNING: Cluster1 - nettest image pull failed"
    if [ -n "$NETTEST_IMAGE_C1" ]; then
        echo "  Image: ${NETTEST_IMAGE_C1}"
    fi
    NETTEST_IMAGE_FAILED=true
fi

if grep -q "ImagePullBackOff.*nettest\|ErrImagePull.*nettest\|unauthorized.*nettest" "${OUTPUT_DIR}/cluster2/subctl-diagnose-all.txt" 2>/dev/null; then
    NETTEST_IMAGE_C2=$(grep -oE '(registry[^"[:space:]]*nettest[^"[:space:]]*)' "${OUTPUT_DIR}/cluster2/subctl-diagnose-all.txt" 2>/dev/null | head -1)
    echo "⚠ WARNING: Cluster2 - nettest image pull failed"
    if [ -n "$NETTEST_IMAGE_C2" ]; then
        echo "  Image: ${NETTEST_IMAGE_C2}"
    fi
    NETTEST_IMAGE_FAILED=true
fi

if [ "$NETTEST_IMAGE_FAILED" = "true" ]; then
    echo ""
    echo "========================================"
    echo "ACTION REQUIRED: Fix nettest Image Access"
    echo "========================================"
    echo ""
    echo "The 'subctl diagnose' test 'Checking that gateway metrics are accessible from"
    echo "non-gateway nodes' failed because it cannot pull the nettest image."
    echo ""
    echo "The nettest image is configured in the Submariner CR (spec.repository and spec.version)."
    echo ""
    echo "Common causes:"
    echo "  - Air-gapped/disconnected deployment: nettest image not mirrored to local registry"
    echo "  - Registry authentication: credentials not configured for image pull"
    echo "  - Network issues: cannot reach the configured image registry"
    echo ""
    echo "Recommended actions:"
    echo "  1. Mirror the nettest image to your accessible registry (for air-gapped deployments)"
    echo "  2. Configure image pull secrets if registry requires authentication"
    echo "  3. Update Submariner CR spec.imageOverrides to use accessible image location"
    echo "  4. Re-run this diagnostic collection script after fixing image availability"
    echo ""
    echo "Note: This does NOT affect core Submariner functionality, only diagnostic tests."
    echo "      The 'subctl verify' tests use quay.io/submariner/nettest:devel as a workaround."
    echo ""

    # Document in manifest
    echo "Image Pull Issues Detected:" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  ⚠ nettest image pull failures in subctl diagnose output" >> "${OUTPUT_DIR}/manifest.txt"
    if [ -n "$NETTEST_IMAGE_C1" ]; then
        echo "  Cluster1 image: ${NETTEST_IMAGE_C1}" >> "${OUTPUT_DIR}/manifest.txt"
    fi
    if [ -n "$NETTEST_IMAGE_C2" ]; then
        echo "  Cluster2 image: ${NETTEST_IMAGE_C2}" >> "${OUTPUT_DIR}/manifest.txt"
    fi
    echo "  Affected test: 'Checking that gateway metrics are accessible from non-gateway nodes'" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Action required: Fix nettest image availability and re-run collection" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  See console output above for detailed remediation steps" >> "${OUTPUT_DIR}/manifest.txt"
    echo "" >> "${OUTPUT_DIR}/manifest.txt"
fi

# Check tunnel status and collect tcpdump if tunnel is not connected
echo ""
echo "=== Checking tunnel status ==="
TUNNEL_STATUS_CLUSTER1=$(grep -A 2 "Showing Connections" "${OUTPUT_DIR}/cluster1/subctl-show-all.txt" | tail -n 1 | awk '{print $(NF-1)}' 2>/dev/null || echo "unknown")
TUNNEL_STATUS_CLUSTER2=$(grep -A 2 "Showing Connections" "${OUTPUT_DIR}/cluster2/subctl-show-all.txt" | tail -n 1 | awk '{print $(NF-1)}' 2>/dev/null || echo "unknown")

echo "Tunnel status:"
echo "  Cluster1: ${TUNNEL_STATUS_CLUSTER1}"
echo "  Cluster2: ${TUNNEL_STATUS_CLUSTER2}"

# Collect tcpdump only if tunnel is NOT connected on either cluster
if [ "$TUNNEL_STATUS_CLUSTER1" != "connected" ] || [ "$TUNNEL_STATUS_CLUSTER2" != "connected" ]; then
    echo ""
    echo "=== Tunnel not fully connected - collecting tcpdump data ==="
    echo "This will help diagnose whether packets are reaching the gateway nodes."
    echo ""

    mkdir -p "${OUTPUT_DIR}/tcpdump"

    echo "tcpdump Data Collection:" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Reason: Tunnel not connected on one or both clusters" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Cluster1 status: ${TUNNEL_STATUS_CLUSTER1}" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Cluster2 status: ${TUNNEL_STATUS_CLUSTER2}" >> "${OUTPUT_DIR}/manifest.txt"
    echo "" >> "${OUTPUT_DIR}/manifest.txt"

    # Collect from both clusters in parallel (background processes)
    collect_tcpdump_from_cluster "cluster1" "${KUBECONFIG1}" "${CLUSTER1_CONTEXT}" "${OUTPUT_DIR}/tcpdump" 80 &
    PID1=$!

    collect_tcpdump_from_cluster "cluster2" "${KUBECONFIG2}" "${CLUSTER2_CONTEXT}" "${OUTPUT_DIR}/tcpdump" 80 &
    PID2=$!

    # Wait for both to complete
    echo "  Waiting for tcpdump collection to complete on both clusters..."
    wait $PID1
    wait $PID2

    echo ""
    echo "✓ tcpdump collection complete"

    # Check if any pcap files were collected
    PCAP_COUNT=$(find "${OUTPUT_DIR}/tcpdump" -name "*.pcap" 2>/dev/null | wc -l)
    ANALYSIS_COUNT=$(find "${OUTPUT_DIR}/tcpdump" -name "*-analysis.txt" 2>/dev/null | wc -l)
    if [ "$PCAP_COUNT" -eq 0 ] && [ "$ANALYSIS_COUNT" -eq 0 ]; then
        echo "  ⚠ No files were collected (no traffic detected)"
        echo "  This may indicate that gateway pods are not sending ESP/UDP tunnel traffic."
        rmdir "${OUTPUT_DIR}/tcpdump" 2>/dev/null
    else
        if [ "$PCAP_COUNT" -gt 0 ]; then
            echo "  ✓ Collected ${PCAP_COUNT} pcap file(s) and ${ANALYSIS_COUNT} analysis file(s)"
        else
            echo "  ✓ Collected ${ANALYSIS_COUNT} analysis file(s) (no traffic captured)"
        fi
        echo "  These files provide packet-level diagnostics for offline analysis."
    fi
else
    echo "  ✓ Tunnel connected on both clusters - skipping tcpdump collection"
    echo ""  >> "${OUTPUT_DIR}/manifest.txt"
    echo "tcpdump Collection: Skipped (tunnel connected on both clusters)" >> "${OUTPUT_DIR}/manifest.txt"
fi

# Firewall diagnostics collection
echo ""
echo "=== Checking firewall diagnostics requirements ==="
mkdir -p "${OUTPUT_DIR}/firewall"

# Determine if we should run inter-cluster firewall diagnostics
# Case A: Inter-cluster firewall diagnostics
# Requirements:
#   1. At least one tunnel is NOT in connected state
#   2. Cable driver uses UDP encapsulation (VxLAN OR IPSec with NAT-T)
# Note: Skip if using IPSec with ESP (protocol 50) - diagnose firewall inter-cluster only checks UDP ports
RUN_FIREWALL_INTER_CLUSTER=false

if [ "$TUNNEL_STATUS_CLUSTER1" != "connected" ] || [ "$TUNNEL_STATUS_CLUSTER2" != "connected" ]; then
    echo "Checking if inter-cluster firewall diagnostics should run..."
    echo "  Reason: At least one tunnel is not in connected state"

    # Get cable driver and encapsulation info from cluster1
    CABLE_DRIVER_C1=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${KUBECONFIG1}" --context="${CLUSTER1_CONTEXT}" -o jsonpath='{.spec.cableDriver}' 2>/dev/null)
    CABLE_DRIVER_C1=${CABLE_DRIVER_C1:-libreswan}
    USING_IP_C1=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${KUBECONFIG1}" --context="${CLUSTER1_CONTEXT}" -o jsonpath='{.status.gateways[0].connections[0].usingIP}' 2>/dev/null)
    PRIVATE_IP_C1=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${KUBECONFIG1}" --context="${CLUSTER1_CONTEXT}" -o jsonpath='{.status.gateways[0].connections[0].endpoint.private_ip}' 2>/dev/null)
    FORCE_UDP_C1=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${KUBECONFIG1}" --context="${CLUSTER1_CONTEXT}" -o jsonpath='{.spec.ceIPSecForceUDPEncaps}' 2>/dev/null)
    NATT_PORT_C1=$(kubectl get submariner submariner -n submariner-operator --kubeconfig="${KUBECONFIG1}" --context="${CLUSTER1_CONTEXT}" -o jsonpath='{.spec.ceIPSecNATTPort}' 2>/dev/null)
    NATT_PORT_C1=${NATT_PORT_C1:-4500}  # Default to 4500 if not set

    # Determine if using UDP encapsulation
    USING_UDP_ENCAP=false
    if [ "$CABLE_DRIVER_C1" = "vxlan" ]; then
        USING_UDP_ENCAP=true
        echo "  Cable driver: VxLAN (uses UDP encapsulation on port ${NATT_PORT_C1})"
    elif [ "$CABLE_DRIVER_C1" = "libreswan" ] || [ "$CABLE_DRIVER_C1" = "ipsec" ]; then
        if [ "$FORCE_UDP_C1" = "true" ] || ( [ -n "$USING_IP_C1" ] && [ -n "$PRIVATE_IP_C1" ] && [ "$USING_IP_C1" != "$PRIVATE_IP_C1" ] ); then
            USING_UDP_ENCAP=true
            echo "  Cable driver: IPSec with UDP encapsulation (NAT-T port ${NATT_PORT_C1})"
        else
            echo "  Cable driver: IPSec with ESP (protocol 50, no UDP encapsulation)"
            echo "  → 'diagnose firewall inter-cluster' is not useful for ESP - it only checks UDP ports"
            echo "  → Will rely on tcpdump data from gateway nodes instead"
        fi
    else
        echo "  Cable driver: ${CABLE_DRIVER_C1}"
    fi

    if [ "$USING_UDP_ENCAP" = "true" ]; then
        RUN_FIREWALL_INTER_CLUSTER=true
        echo "  ✓ Will run inter-cluster firewall diagnostics (tunnel not connected + UDP encapsulation)"
    else
        echo "  → Skipping inter-cluster firewall diagnostics (not using UDP encapsulation)"
    fi
else
    echo "  → Skipping inter-cluster firewall diagnostics (tunnels connected on both clusters)"
fi

# Run inter-cluster firewall diagnostics if conditions are met
if [ "$RUN_FIREWALL_INTER_CLUSTER" = "true" ]; then
    echo ""
    echo "Firewall Inter-Cluster Diagnostics:" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Reason: Tunnel not connected + UDP encapsulation detected" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Cable driver: ${CABLE_DRIVER_C1}" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  NAT-T port: ${NATT_PORT_C1}" >> "${OUTPUT_DIR}/manifest.txt"
    echo "" >> "${OUTPUT_DIR}/manifest.txt"

    # Use IMAGE_OVERRIDE variable if already set from verify section, otherwise use quay.io as default
    if [ -z "$IMAGE_OVERRIDE" ]; then
        # Use quay.io as default for upstream Submariner
        FIREWALL_IMAGE_OVERRIDE="--image-override submariner-nettest=quay.io/submariner/nettest:devel"
    else
        FIREWALL_IMAGE_OVERRIDE="$IMAGE_OVERRIDE"
    fi

    collect_firewall_inter_cluster "${CLUSTER1_CONTEXT}" "${KUBECONFIG1}" "${CLUSTER2_CONTEXT}" "${KUBECONFIG2}" "${OUTPUT_DIR}/firewall" "${FIREWALL_IMAGE_OVERRIDE}"
else
    echo "" >> "${OUTPUT_DIR}/manifest.txt"
    echo "Firewall Inter-Cluster Diagnostics: Skipped (requirements not met)" >> "${OUTPUT_DIR}/manifest.txt"
fi

# Determine if we should run intra-cluster firewall diagnostics
# Case B: Intra-cluster firewall diagnostics
# Requirements:
#   1. CNI is NOT OVN-Kubernetes (checked per cluster independently)
#   2. Runs REGARDLESS of tunnel status
# Note: If there are intra-cluster firewall issues, we expect to see:
#   - Failures in RouteAgent resources
#   - subctl verify tests from pods on non-gateway nodes should fail
echo ""
echo "Checking if intra-cluster firewall diagnostics should run (Case B)..."
echo "  Note: This is checked per cluster and runs regardless of tunnel status"

# Detect CNI from both clusters
# Note: This detection happens before the verify section, so we need to check if gather has completed
CNI_CLUSTER1=""
CNI_CLUSTER2=""
CLUSTER1_SUMMARY=$(find "${OUTPUT_DIR}/cluster1/gather" -name summary.html -print -quit 2>/dev/null)
CLUSTER2_SUMMARY=$(find "${OUTPUT_DIR}/cluster2/gather" -name summary.html -print -quit 2>/dev/null)

if [ -n "${CLUSTER1_SUMMARY}" ]; then
    CNI_CLUSTER1=$(grep -A 1 "CNI Plugin:" "${CLUSTER1_SUMMARY}" 2>/dev/null | grep -oP '<td>\K[^<]+' | tail -1 | tr -d '[:space:]')
fi
if [ -n "${CLUSTER2_SUMMARY}" ]; then
    CNI_CLUSTER2=$(grep -A 1 "CNI Plugin:" "${CLUSTER2_SUMMARY}" 2>/dev/null | grep -oP '<td>\K[^<]+' | tail -1 | tr -d '[:space:]')
fi

echo "  Cluster1 CNI: ${CNI_CLUSTER1:-unknown}"
echo "  Cluster2 CNI: ${CNI_CLUSTER2:-unknown}"

# Check each cluster independently
RUN_FIREWALL_INTRA_CLUSTER1=false
if [ "$CNI_CLUSTER1" != "OVNKubernetes" ] && [ -n "$CNI_CLUSTER1" ]; then
    RUN_FIREWALL_INTRA_CLUSTER1=true
    echo "  ✓ Will run intra-cluster firewall diagnostics for cluster1 (CNI is ${CNI_CLUSTER1})"
else
    echo "  → Skipping intra-cluster firewall diagnostics for cluster1 (CNI is OVNK or unknown)"
fi

RUN_FIREWALL_INTRA_CLUSTER2=false
if [ "$CNI_CLUSTER2" != "OVNKubernetes" ] && [ -n "$CNI_CLUSTER2" ]; then
    RUN_FIREWALL_INTRA_CLUSTER2=true
    echo "  ✓ Will run intra-cluster firewall diagnostics for cluster2 (CNI is ${CNI_CLUSTER2})"
else
    echo "  → Skipping intra-cluster firewall diagnostics for cluster2 (CNI is OVNK or unknown)"
fi

# Setup image override if needed (for both clusters)
if [ "$RUN_FIREWALL_INTRA_CLUSTER1" = "true" ] || [ "$RUN_FIREWALL_INTRA_CLUSTER2" = "true" ]; then
    # Use the same image override as inter-cluster if available, otherwise use quay.io as default
    if [ -z "$FIREWALL_IMAGE_OVERRIDE" ]; then
        # Use quay.io as default for upstream Submariner
        FIREWALL_IMAGE_OVERRIDE="--image-override submariner-nettest=quay.io/submariner/nettest:devel"
    fi
fi

# Run intra-cluster firewall diagnostics for cluster1 (independent of cluster2)
if [ "$RUN_FIREWALL_INTRA_CLUSTER1" = "true" ]; then
    echo ""
    echo "Firewall Intra-Cluster Diagnostics (Cluster1):" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Reason: CNI is ${CNI_CLUSTER1} (not OVNK)" >> "${OUTPUT_DIR}/manifest.txt"
    echo "" >> "${OUTPUT_DIR}/manifest.txt"

    collect_firewall_intra_cluster "cluster1" "${KUBECONFIG1}" "${CLUSTER1_CONTEXT}" "${OUTPUT_DIR}/firewall" "${FIREWALL_IMAGE_OVERRIDE}"
fi

# Run intra-cluster firewall diagnostics for cluster2 (independent of cluster1)
if [ "$RUN_FIREWALL_INTRA_CLUSTER2" = "true" ]; then
    echo ""
    echo "Firewall Intra-Cluster Diagnostics (Cluster2):" >> "${OUTPUT_DIR}/manifest.txt"
    echo "  Reason: CNI is ${CNI_CLUSTER2} (not OVNK)" >> "${OUTPUT_DIR}/manifest.txt"
    echo "" >> "${OUTPUT_DIR}/manifest.txt"

    collect_firewall_intra_cluster "cluster2" "${KUBECONFIG2}" "${CLUSTER2_CONTEXT}" "${OUTPUT_DIR}/firewall" "${FIREWALL_IMAGE_OVERRIDE}"
fi

# Run connectivity verification
echo ""
echo "=== Checking connectivity verification eligibility ==="
mkdir -p "${OUTPUT_DIR}/verify"

# Use the tunnel status already determined
TUNNEL_STATUS_CLUSTER1=${TUNNEL_STATUS_CLUSTER1:-$(grep -A 2 "Showing Connections" "${OUTPUT_DIR}/cluster1/subctl-show-all.txt" | tail -n 1 | awk '{print $(NF-1)}' 2>/dev/null || echo "unknown")}
TUNNEL_STATUS_CLUSTER2=${TUNNEL_STATUS_CLUSTER2:-$(grep -A 2 "Showing Connections" "${OUTPUT_DIR}/cluster2/subctl-show-all.txt" | tail -n 1 | awk '{print $(NF-1)}' 2>/dev/null || echo "unknown")}

echo "Tunnel status:"
echo "  Cluster1: ${TUNNEL_STATUS_CLUSTER1}"
echo "  Cluster2: ${TUNNEL_STATUS_CLUSTER2}"

# Skip subctl verify only if tunnel is not connected on BOTH clusters
# If one tunnel is connected but the other is not, we still run verification to diagnose the asymmetry
if [ "$TUNNEL_STATUS_CLUSTER1" != "connected" ] && [ "$TUNNEL_STATUS_CLUSTER2" != "connected" ]; then
    echo ""
    echo "  ✗ Tunnel NOT connected on either cluster - skipping 'subctl verify'"
    echo "  → Reason: Need to establish basic tunnel connectivity first"
    echo "  → Alternative: tcpdump data provides packet-level diagnostics (see tcpdump/ directory)"
    echo ""

    # Create skip notes for all verify files
    echo "========================================" > "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "CONNECTIVITY VERIFICATION SKIPPED" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "========================================" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "Connectivity verification was skipped because tunnel status is not 'connected' on either cluster." >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "Tunnel status:" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  Cluster1: ${TUNNEL_STATUS_CLUSTER1}" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  Cluster2: ${TUNNEL_STATUS_CLUSTER2}" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "Why skipped:" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  - Both tunnels are not connected - no connectivity possible" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  - Focus should be on establishing basic tunnel connectivity first" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  - tcpdump packet captures (if collected) provide better diagnostics for tunnel failures" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "Recommended diagnostics for tunnel failures:" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  1. Check tcpdump/ directory for packet-level analysis" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  2. Review cluster*/subctl-diagnose-all.txt for health check results" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  3. Review cluster*/gather/cluster*/ipsec-status.log for IPsec tunnel state" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "To run connectivity tests, fix the tunnel issue first, then re-collect diagnostics." >> "${OUTPUT_DIR}/verify/connectivity.txt"

    cp "${OUTPUT_DIR}/verify/connectivity.txt" "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
    cp "${OUTPUT_DIR}/verify/connectivity.txt" "${OUTPUT_DIR}/verify/service-discovery.txt"

    # Skip the entire verify section
    SKIP_VERIFY=true
elif [ "$TUNNEL_STATUS_CLUSTER1" = "connected" ] && [ "$TUNNEL_STATUS_CLUSTER2" = "connected" ]; then
    echo ""
    echo "  ✓ Tunnel status: connected on BOTH clusters"
    echo "  → Will run full connectivity verification tests (including MTU test)"

    SKIP_VERIFY=false
    VERIFY_CONNECTIVITY_FLAG="connectivity"
    RUN_MTU_TEST=true
else
    echo ""
    echo "  ⚠ Asymmetric tunnel status detected (connected on one cluster, not on the other)"
    echo "  → Will run connectivity verification to diagnose the issue"
    echo "  → Note: This may indicate a SNAT or routing issue affecting one direction"

    SKIP_VERIFY=false
    VERIFY_CONNECTIVITY_FLAG="connectivity"
    RUN_MTU_TEST=false
fi

# Only run verify tests if tunnel is connected on at least one cluster
if [ "$SKIP_VERIFY" = "false" ]; then
    echo ""
    # Use quay.io as default for upstream Submariner
    echo "Using quay.io/submariner/nettest:devel as default image..."
    IMAGE_OVERRIDE="--image-override submariner-nettest=quay.io/submariner/nettest:devel"

    # Merge kubeconfigs temporarily for subctl verify
    MERGED_KUBECONFIG="${OUTPUT_DIR}/merged-kubeconfig"
    KUBECONFIG="${KUBECONFIG1}:${KUBECONFIG2}" kubectl config view --flatten > "${MERGED_KUBECONFIG}"

    echo ""
    echo "Running subctl verify for connectivity (using --only ${VERIFY_CONNECTIVITY_FLAG})..."
    echo "  Start time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    echo "  Note: Verification tests may take 20-30 minutes if connectivity issues exist"
    echo "        Tests will stop early if first 6 tests fail (indicating systemic issues)"
    echo "        Showing progress every 60 seconds..."
    echo ""

    VERIFY_CMD="KUBECONFIG=${MERGED_KUBECONFIG} subctl verify --context ${CLUSTER1_CONTEXT} --tocontext ${CLUSTER2_CONTEXT} --only ${VERIFY_CONNECTIVITY_FLAG} --connection-timeout 50 --verbose ${IMAGE_OVERRIDE}"
    echo "========================================" > "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "Command executed:" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "${VERIFY_CMD}" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "========================================" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"

    # Run verify in background with progress monitoring
    VERIFY_TIMEOUT=1800  # 30 minutes max
    PROGRESS_INTERVAL=60  # Show progress every 60 seconds
    EARLY_STOP_THRESHOLD=6  # Stop early if first 6 tests all fail

    (
        KUBECONFIG="${MERGED_KUBECONFIG}" subctl verify \
            --context "${CLUSTER1_CONTEXT}" \
            --tocontext "${CLUSTER2_CONTEXT}" \
            --only "${VERIFY_CONNECTIVITY_FLAG}" \
            --connection-timeout 50 \
            --verbose ${IMAGE_OVERRIDE} \
            >> "${OUTPUT_DIR}/verify/connectivity.txt" 2>&1
    ) &
    VERIFY_PID=$!

    # Monitor progress and check for early-stop condition
    elapsed=0
    while kill -0 $VERIFY_PID 2>/dev/null; do
        # Check timeout
        if [ $elapsed -ge $VERIFY_TIMEOUT ]; then
            echo "  ⚠ Verify tests exceeded ${VERIFY_TIMEOUT}s timeout - terminating"
            kill $VERIFY_PID 2>/dev/null
            echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
            echo "Verification terminated after ${VERIFY_TIMEOUT}s timeout" >> "${OUTPUT_DIR}/verify/connectivity.txt"
            break
        fi

        # Check if we should stop early due to consistent failures
        # Count completed tests (each test ends with "• [X.XXX seconds]")
        if [ -f "${OUTPUT_DIR}/verify/connectivity.txt" ]; then
            completed_tests=$(grep -c "\[.*seconds\]" "${OUTPUT_DIR}/verify/connectivity.txt" 2>/dev/null | tr -d '\n\r' || echo "0")
            # Ensure it's a valid number
            if ! [[ "$completed_tests" =~ ^[0-9]+$ ]]; then
                completed_tests=0
            fi
        else
            completed_tests=0
        fi

        if [ "$completed_tests" -ge "$EARLY_STOP_THRESHOLD" 2>/dev/null ]; then
            # Check if tests have completed normally (final summary exists)
            if ! grep -q "^Ran.*Specs" "${OUTPUT_DIR}/verify/connectivity.txt" 2>/dev/null; then
                # Tests still running - check if tests are failing
                # Ginkgo shows failures with FAIL or timeout messages
                failure_blocks=$(grep -c "FAIL\|timed out\|refused" "${OUTPUT_DIR}/verify/connectivity.txt" 2>/dev/null || echo "0")

                if [ "$failure_blocks" -ge "$EARLY_STOP_THRESHOLD" ]; then
                    echo "  ⚠ First $completed_tests tests failing - stopping early to save time"
                    echo "     (Collected enough diagnostic data to identify connectivity issues)"
                    kill $VERIFY_PID 2>/dev/null
                    echo "" >> "${OUTPUT_DIR}/verify/connectivity.txt"
                    echo "Verification stopped early after $completed_tests consecutive test failures" >> "${OUTPUT_DIR}/verify/connectivity.txt"
                    echo "This indicates systemic connectivity issues - see failed test details above" >> "${OUTPUT_DIR}/verify/connectivity.txt"
                    break
                fi
            fi
        fi

        sleep $PROGRESS_INTERVAL
        elapsed=$((elapsed + PROGRESS_INTERVAL))
        if [ "$completed_tests" -gt 0 ]; then
            echo "  ... still running (${elapsed}s elapsed, $completed_tests tests completed)"
        else
            echo "  ... still running (${elapsed}s elapsed)"
        fi
    done

    wait $VERIFY_PID 2>/dev/null || echo "Connectivity verification failed or timed out" >> "${OUTPUT_DIR}/verify/connectivity.txt"
    echo "  End time: $(date '+%Y-%m-%d %H:%M:%S')"

    # Check if regular connectivity test passed
    CONNECTIVITY_PASSED=false
    if [ -f "${OUTPUT_DIR}/verify/connectivity.txt" ]; then
        if grep -qE "SUCCESS!|[0-9]+\s+Passed.*0\s+Failed" "${OUTPUT_DIR}/verify/connectivity.txt" 2>/dev/null; then
            CONNECTIVITY_PASSED=true
        fi
    fi

    # Skip small packet test if regular test passed (no point - large packets already work)
    if [ "$RUN_MTU_TEST" = "true" ] && [ "$CONNECTIVITY_PASSED" = "true" ]; then
        echo ""
        echo "Skipping small packet test - regular connectivity test already passed"
        echo "  (Small packet test is only useful to detect MTU issues when large packets fail)"
        echo ""

        echo "========================================" > "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "SMALL PACKET TEST SKIPPED" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "========================================" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "Small packet test was skipped because regular connectivity test passed." >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "The small packet test (--packet-size 400) is only useful to detect MTU/fragmentation" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "issues where large packets fail but small packets succeed. Since large packets are" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "already working, there is no need to test small packets." >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "Regular connectivity test result: PASSED" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"

        RUN_MTU_TEST=false
    fi

    if [ "$RUN_MTU_TEST" = "true" ]; then
        echo ""
        echo "Running subctl verify for connectivity (small packet size for MTU testing)..."
        echo "  Start time: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Note: Showing progress every 60 seconds..."
        echo ""

        VERIFY_CMD="KUBECONFIG=${MERGED_KUBECONFIG} subctl verify --context ${CLUSTER1_CONTEXT} --tocontext ${CLUSTER2_CONTEXT} --only connectivity --connection-timeout 50 --verbose --packet-size 400 ${IMAGE_OVERRIDE}"
        echo "========================================" > "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "Command executed:" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "${VERIFY_CMD}" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "========================================" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"

        # Run verify in background with progress monitoring
        (
            KUBECONFIG="${MERGED_KUBECONFIG}" subctl verify \
                --context "${CLUSTER1_CONTEXT}" \
                --tocontext "${CLUSTER2_CONTEXT}" \
                --only connectivity \
                --connection-timeout 50 \
                --verbose \
                --packet-size 400 \
                ${IMAGE_OVERRIDE} \
                >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt" 2>&1
        ) &
        VERIFY_PID=$!

        # Monitor progress and check for early-stop condition
        elapsed=0
        while kill -0 $VERIFY_PID 2>/dev/null; do
            # Check timeout
            if [ $elapsed -ge $VERIFY_TIMEOUT ]; then
                echo "  ⚠ MTU test exceeded ${VERIFY_TIMEOUT}s timeout - terminating"
                kill $VERIFY_PID 2>/dev/null
                echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
                echo "Verification terminated after ${VERIFY_TIMEOUT}s timeout" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
                break
            fi

            # Check if we should stop early due to consistent failures
            if [ -f "${OUTPUT_DIR}/verify/connectivity-small-packet.txt" ]; then
                completed_tests=$(grep -c "\[.*seconds\]" "${OUTPUT_DIR}/verify/connectivity-small-packet.txt" 2>/dev/null | tr -d '\n\r' || echo "0")
                # Ensure it's a valid number
                if ! [[ "$completed_tests" =~ ^[0-9]+$ ]]; then
                    completed_tests=0
                fi
            else
                completed_tests=0
            fi

            if [ "$completed_tests" -ge "$EARLY_STOP_THRESHOLD" 2>/dev/null ]; then
                if ! grep -q "^Ran.*Specs" "${OUTPUT_DIR}/verify/connectivity-small-packet.txt" 2>/dev/null; then
                    failure_blocks=$(grep -c "FAIL\|timed out\|refused" "${OUTPUT_DIR}/verify/connectivity-small-packet.txt" 2>/dev/null || echo "0")

                    if [ "$failure_blocks" -ge "$EARLY_STOP_THRESHOLD" ]; then
                        echo "  ⚠ First $completed_tests MTU tests failing - stopping early to save time"
                        echo "     (Collected enough diagnostic data to identify MTU/packet size issues)"
                        kill $VERIFY_PID 2>/dev/null
                        echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
                        echo "Verification stopped early after $completed_tests consecutive test failures" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
                        echo "This indicates systemic connectivity issues - see failed test details above" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
                        break
                    fi
                fi
            fi

            sleep $PROGRESS_INTERVAL
            elapsed=$((elapsed + PROGRESS_INTERVAL))
            if [ "$completed_tests" -gt 0 ]; then
                echo "  ... still running (${elapsed}s elapsed, $completed_tests tests completed)"
            else
                echo "  ... still running (${elapsed}s elapsed)"
            fi
        done

        wait $VERIFY_PID 2>/dev/null || echo "Connectivity verification with small packets failed or timed out" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        echo "  End time: $(date '+%Y-%m-%d %H:%M:%S')"
    else
        # Only write skip message if file doesn't already exist (avoid overwriting earlier skip message)
        if [ ! -f "${OUTPUT_DIR}/verify/connectivity-small-packet.txt" ]; then
            echo "Skipping MTU test (tunnel connected on only one cluster)"
            echo "========================================" > "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
            echo "MTU TEST SKIPPED" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
            echo "========================================" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
            echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
            echo "MTU test was skipped because tunnel is only connected on one cluster." >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
            echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
            echo "Tunnel status:" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
            echo "  Cluster1: ${TUNNEL_STATUS_CLUSTER1}" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
            echo "  Cluster2: ${TUNNEL_STATUS_CLUSTER2}" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
            echo "" >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
            echo "MTU testing requires tunnel connected on both clusters." >> "${OUTPUT_DIR}/verify/connectivity-small-packet.txt"
        fi
    fi

    # Check if service discovery is enabled before running the test
    echo ""
    echo "Checking if service discovery is enabled..."
    SD_ENABLED_CLUSTER1=$(kubectl get submariner submariner -n submariner-operator --kubeconfig "${KUBECONFIG1}" --context "${CLUSTER1_CONTEXT}" -o jsonpath='{.spec.serviceDiscoveryEnabled}' 2>/dev/null)
    SD_ENABLED_CLUSTER2=$(kubectl get submariner submariner -n submariner-operator --kubeconfig "${KUBECONFIG2}" --context "${CLUSTER2_CONTEXT}" -o jsonpath='{.spec.serviceDiscoveryEnabled}' 2>/dev/null)

    if [ "$SD_ENABLED_CLUSTER1" = "true" ] || [ "$SD_ENABLED_CLUSTER2" = "true" ]; then
        echo ""
        echo "Running subctl verify for service-discovery..."
        echo "  Start time: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "  Note: Showing progress every 60 seconds..."
        echo ""

        VERIFY_CMD="KUBECONFIG=${MERGED_KUBECONFIG} subctl verify --context ${CLUSTER1_CONTEXT} --tocontext ${CLUSTER2_CONTEXT} --only service-discovery --connection-timeout 50 --verbose ${IMAGE_OVERRIDE}"
        echo "========================================" > "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "Command executed:" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "${VERIFY_CMD}" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "========================================" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "" >> "${OUTPUT_DIR}/verify/service-discovery.txt"

        # Run verify in background with progress monitoring
        (
            KUBECONFIG="${MERGED_KUBECONFIG}" subctl verify \
                --context "${CLUSTER1_CONTEXT}" \
                --tocontext "${CLUSTER2_CONTEXT}" \
                --only service-discovery \
                --connection-timeout 50 \
                --verbose \
                ${IMAGE_OVERRIDE} \
                >> "${OUTPUT_DIR}/verify/service-discovery.txt" 2>&1
        ) &
        VERIFY_PID=$!

        # Monitor progress and check for early-stop condition
        elapsed=0
        while kill -0 $VERIFY_PID 2>/dev/null; do
            # Check timeout
            if [ $elapsed -ge $VERIFY_TIMEOUT ]; then
                echo "  ⚠ Service discovery test exceeded ${VERIFY_TIMEOUT}s timeout - terminating"
                kill $VERIFY_PID 2>/dev/null
                echo "" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
                echo "Verification terminated after ${VERIFY_TIMEOUT}s timeout" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
                break
            fi

            # Check if we should stop early due to consistent failures
            if [ -f "${OUTPUT_DIR}/verify/service-discovery.txt" ]; then
                completed_tests=$(grep -c "\[.*seconds\]" "${OUTPUT_DIR}/verify/service-discovery.txt" 2>/dev/null | tr -d '\n\r' || echo "0")
                # Ensure it's a valid number
                if ! [[ "$completed_tests" =~ ^[0-9]+$ ]]; then
                    completed_tests=0
                fi
            else
                completed_tests=0
            fi

            if [ "$completed_tests" -ge "$EARLY_STOP_THRESHOLD" 2>/dev/null ]; then
                if ! grep -q "^Ran.*Specs" "${OUTPUT_DIR}/verify/service-discovery.txt" 2>/dev/null; then
                    failure_blocks=$(grep -c "FAIL\|timed out\|refused" "${OUTPUT_DIR}/verify/service-discovery.txt" 2>/dev/null || echo "0")

                    if [ "$failure_blocks" -ge "$EARLY_STOP_THRESHOLD" ]; then
                        echo "  ⚠ First $completed_tests service discovery tests failing - stopping early to save time"
                        echo "     (Collected enough diagnostic data to identify service discovery issues)"
                        kill $VERIFY_PID 2>/dev/null
                        echo "" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
                        echo "Verification stopped early after $completed_tests consecutive test failures" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
                        echo "This indicates systemic service discovery issues - see failed test details above" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
                        break
                    fi
                fi
            fi

            sleep $PROGRESS_INTERVAL
            elapsed=$((elapsed + PROGRESS_INTERVAL))
            if [ "$completed_tests" -gt 0 ]; then
                echo "  ... still running (${elapsed}s elapsed, $completed_tests tests completed)"
            else
                echo "  ... still running (${elapsed}s elapsed)"
            fi
        done

        wait $VERIFY_PID 2>/dev/null || echo "Service discovery verification failed or timed out" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "  End time: $(date '+%Y-%m-%d %H:%M:%S')"
    else
        echo "Skipping service-discovery verification (not enabled on either cluster)"
        echo "========================================" > "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "SERVICE DISCOVERY VERIFICATION SKIPPED" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "========================================" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "Service discovery is not enabled on either cluster." >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "Cluster1 serviceDiscoveryEnabled: ${SD_ENABLED_CLUSTER1:-not set (defaults to false)}" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "Cluster2 serviceDiscoveryEnabled: ${SD_ENABLED_CLUSTER2:-not set (defaults to false)}" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
        echo "To enable service discovery, see: https://submariner.io/getting-started/quickstart/openshift/service-discovery/" >> "${OUTPUT_DIR}/verify/service-discovery.txt"
    fi

    # Check for OVNK-specific SNAT issue
    echo ""
    echo "Checking for OVNK-specific issues..."

    # Detect CNI from both clusters using summary.html (more reliable than subctl show output)
    CLUSTER1_SUMMARY=$(find "${OUTPUT_DIR}/cluster1/gather" -name summary.html -print -quit 2>/dev/null)
    CLUSTER2_SUMMARY=$(find "${OUTPUT_DIR}/cluster2/gather" -name summary.html -print -quit 2>/dev/null)

    if [ -n "${CLUSTER1_SUMMARY}" ]; then
        CNI_CLUSTER1=$(grep -A 1 "CNI Plugin:" "${CLUSTER1_SUMMARY}" 2>/dev/null | grep -oP '<td>\K[^<]+' | tail -1 | tr -d '[:space:]')
    fi
    if [ -n "${CLUSTER2_SUMMARY}" ]; then
        CNI_CLUSTER2=$(grep -A 1 "CNI Plugin:" "${CLUSTER2_SUMMARY}" 2>/dev/null | grep -oP '<td>\K[^<]+' | tail -1 | tr -d '[:space:]')
    fi

    echo "  Cluster1 CNI: ${CNI_CLUSTER1:-unknown}"
    echo "  Cluster2 CNI: ${CNI_CLUSTER2:-unknown}"

    # Check if either cluster uses OVNK (OVNKubernetes)
    OVNK_DETECTED=false
    if [[ "$CNI_CLUSTER1" == "OVNKubernetes" ]] || [[ "$CNI_CLUSTER2" == "OVNKubernetes" ]]; then
        OVNK_DETECTED=true
        echo "  ✓ OVNK CNI detected - will check for SNAT issue if connectivity tests failed"
    else
        echo "  → No OVNK CNI detected - skipping OVNK-specific tests"
    fi

    # Check if connectivity tests failed
    CONNECTIVITY_FAILED=false
    if [ -f "${OUTPUT_DIR}/verify/connectivity.txt" ]; then
        # First check if test passed (avoid false positives from "0 Failed" in success summaries)
        if grep -qE 'SUCCESS!|[0-9]+\s+Passed.*0\s+Failed' "${OUTPUT_DIR}/verify/connectivity.txt" 2>/dev/null; then
            CONNECTIVITY_FAILED=false
        # Only if not successful, check for actual failures (including timeouts)
        elif grep -qE 'FAIL\b|timed out|terminated after|stopped early|[1-9][0-9]*\s+Failed' "${OUTPUT_DIR}/verify/connectivity.txt" 2>/dev/null; then
            CONNECTIVITY_FAILED=true
        fi
    fi

    # Check if small packet tests also failed (to rule out MTU issues)
    SMALL_PACKET_FAILED=false
    SMALL_PACKET_STATUS="not-run"
    if [ -f "${OUTPUT_DIR}/verify/connectivity-small-packet.txt" ]; then
        # Check if test was actually run (not skipped)
        if grep -qE "SKIPPED|MTU TEST SKIPPED|SMALL PACKET TEST SKIPPED" "${OUTPUT_DIR}/verify/connectivity-small-packet.txt" 2>/dev/null; then
            SMALL_PACKET_STATUS="skipped"
        else
            # Test was run - check if it failed (avoid false positives from "0 Failed" in success summaries)
            if grep -qE 'SUCCESS!|[0-9]+\s+Passed.*0\s+Failed' "${OUTPUT_DIR}/verify/connectivity-small-packet.txt" 2>/dev/null; then
                SMALL_PACKET_STATUS="passed"
                SMALL_PACKET_FAILED=false
            # Only if not successful, check for actual failures (including timeouts)
            elif grep -qE 'FAIL\b|timed out|terminated after|stopped early|[1-9][0-9]*\s+Failed' "${OUTPUT_DIR}/verify/connectivity-small-packet.txt" 2>/dev/null; then
                SMALL_PACKET_STATUS="failed"
                SMALL_PACKET_FAILED=true
            fi
        fi
    fi

    # If OVNK detected AND connectivity failed AND small packet also failed (not MTU issue), run verify with --skip-src-ip-check
    # This helps identify the known OVNK SNAT bug that affects Submariner
    if [ "$OVNK_DETECTED" = "true" ] && [ "$CONNECTIVITY_FAILED" = "true" ] && [ "$SMALL_PACKET_FAILED" = "true" ]; then
        echo ""
        echo "Running additional verify test with --skip-src-ip-check (testing for known OVNK SNAT issue)..."
        echo "  This helps identify if the known OVNK SNAT bug is causing connectivity issues"
        echo "  Start time: $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""

        VERIFY_CMD="KUBECONFIG=${MERGED_KUBECONFIG} subctl verify --context ${CLUSTER1_CONTEXT} --tocontext ${CLUSTER2_CONTEXT} --only connectivity --connection-timeout 50 --verbose --skip-src-ip-check ${IMAGE_OVERRIDE}"
        echo "========================================" > "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "Command executed:" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "${VERIFY_CMD}" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "========================================" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "CONTEXT: This test was run because:" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "  - Regular connectivity tests: FAILED" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "  - Small packet size tests: FAILED (rules out MTU issue)" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "  - OVNK CNI detected (Cluster1: ${CNI_CLUSTER1}, Cluster2: ${CNI_CLUSTER2})" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "  - Testing if known OVNK SNAT bug is the root cause" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "If this test passes, it indicates the known OVNK SNAT issue documented at:" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "https://github.com/submariner-io/submariner/issues/3307#issuecomment-2653220140" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"

        # Run verify with --skip-src-ip-check
        (
            KUBECONFIG="${MERGED_KUBECONFIG}" subctl verify \
                --context "${CLUSTER1_CONTEXT}" \
                --tocontext "${CLUSTER2_CONTEXT}" \
                --only connectivity \
                --connection-timeout 50 \
                --verbose \
                --skip-src-ip-check \
                ${IMAGE_OVERRIDE} \
                >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt" 2>&1
        ) &
        VERIFY_PID=$!

        # Wait with progress monitoring
        elapsed=0
        PROGRESS_INTERVAL=60
        VERIFY_TIMEOUT=1800
        while kill -0 $VERIFY_PID 2>/dev/null; do
            if [ $elapsed -ge $VERIFY_TIMEOUT ]; then
                echo "  ⚠ OVNK verify test exceeded ${VERIFY_TIMEOUT}s timeout - terminating"
                kill $VERIFY_PID 2>/dev/null
                echo "" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
                echo "Verification terminated after ${VERIFY_TIMEOUT}s timeout" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
                break
            fi

            sleep $PROGRESS_INTERVAL
            elapsed=$((elapsed + PROGRESS_INTERVAL))
            echo "  ... still running (${elapsed}s elapsed)"
        done

        wait $VERIFY_PID 2>/dev/null || echo "OVNK verify test failed or timed out" >> "${OUTPUT_DIR}/verify/connectivity-skip-src-ip-check.txt"
        echo "  End time: $(date '+%Y-%m-%d %H:%M:%S')"
    elif [ "$CONNECTIVITY_FAILED" = "false" ]; then
        echo "  → Regular connectivity tests passed - no need for OVNK-specific test"
    elif [ "$CONNECTIVITY_FAILED" = "true" ] && [ "$SMALL_PACKET_STATUS" = "passed" ]; then
        echo "  → Small packet test passed but regular failed - this is an MTU issue, not OVNK SNAT"
        echo "     Skipping OVNK-specific test (MTU issue already detected)"
    elif [ "$CONNECTIVITY_FAILED" = "true" ] && [ "$SMALL_PACKET_STATUS" = "skipped" ]; then
        echo "  → Small packet test was skipped - cannot classify this as MTU or OVNK SNAT from this run"
        echo "     In asymmetric tunnel cases, review routing/SNAT guidance and rerun with --skip-src-ip-check if needed"
    elif [ "$CONNECTIVITY_FAILED" = "true" ] && [ "$SMALL_PACKET_STATUS" = "not-run" ]; then
        echo "  → Small packet test did not run - cannot classify this as MTU or OVNK SNAT from this run"
    elif [ "$OVNK_DETECTED" = "false" ]; then
        echo "  → OVNK CNI not detected - skipping OVNK-specific test"
    else
        echo "  → Skipping OVNK-specific test (conditions not met)"
    fi

    # Cleanup merged kubeconfig
    rm -f "${MERGED_KUBECONFIG}"
fi

# Create tarball
echo ""
echo "Creating tarball..."
if tar -czf "${OUTPUT_DIR}.tar.gz" "${OUTPUT_DIR}"; then
    # Cleanup directory (keep only tarball)
    rm -rf "${OUTPUT_DIR}"
else
    echo "ERROR: Failed to create ${OUTPUT_DIR}.tar.gz"
    echo "Keeping ${OUTPUT_DIR} for inspection."
    return 1 2>/dev/null || exit 1
fi

COLLECTION_END_TIME=$(date +%s)
COLLECTION_DURATION=$((COLLECTION_END_TIME - COLLECTION_START_TIME))
COLLECTION_MINUTES=$((COLLECTION_DURATION / 60))
COLLECTION_SECONDS=$((COLLECTION_DURATION % 60))

echo ""
echo "=========================================="
echo "Diagnostic collection complete!"
echo "Output: ${OUTPUT_DIR}.tar.gz"
echo "End time: $(date '+%Y-%m-%d %H:%M:%S')"
echo "Total duration: ${COLLECTION_MINUTES}m ${COLLECTION_SECONDS}s"
echo "=========================================="
echo ""
echo "Contents:"
echo "  - Cluster 1 diagnostics (subctl gather, show, diagnose)"
echo "  - Cluster 2 diagnostics (subctl gather, show, diagnose)"

if [ "$TUNNEL_STATUS_CLUSTER1" != "connected" ] || [ "$TUNNEL_STATUS_CLUSTER2" != "connected" ]; then
    echo "  - tcpdump packet captures from gateway nodes (tunnel not connected)"
fi

# Show firewall diagnostics summary
if [ "$RUN_FIREWALL_INTER_CLUSTER" = "true" ]; then
    echo "  - Firewall inter-cluster diagnostics"
fi

if [ "$RUN_FIREWALL_INTRA_CLUSTER1" = "true" ] || [ "$RUN_FIREWALL_INTRA_CLUSTER2" = "true" ]; then
    if [ "$RUN_FIREWALL_INTRA_CLUSTER1" = "true" ] && [ "$RUN_FIREWALL_INTRA_CLUSTER2" = "true" ]; then
        echo "  - Firewall intra-cluster diagnostics (both clusters)"
    elif [ "$RUN_FIREWALL_INTRA_CLUSTER1" = "true" ]; then
        echo "  - Firewall intra-cluster diagnostics (cluster1)"
    else
        echo "  - Firewall intra-cluster diagnostics (cluster2)"
    fi
fi

if [ "$SKIP_VERIFY" = "true" ]; then
    echo "  - Connectivity verification: SKIPPED (tunnel not connected on either cluster)"
    echo "    → tcpdump data provides packet-level diagnostics instead"
else
    echo "  - Connectivity verification results"
    echo "  - Service discovery verification results"
    if [ "$RUN_MTU_TEST" = "true" ]; then
        echo "  - MTU testing (small packet size)"
    elif [ "$CONNECTIVITY_PASSED" = "true" ]; then
        echo "  - MTU testing: SKIPPED (regular connectivity test passed)"
    else
        echo "  - MTU testing: SKIPPED (tunnel connected on only one cluster)"
    fi
fi
echo "  - RouteAgent status"
echo "  - ACM resources (if present)"
echo ""
echo "Next steps:"
echo "1. Share this tarball with your support team or Submariner expert"
echo "2. They can analyze it offline without needing cluster access"
echo "3. For AI-assisted analysis with Claude Code, run:"
echo "   /submariner:analyze-offline ${OUTPUT_DIR}.tar.gz"
echo ""

# Cleanup temporary kubeconfig if it was created
if [ "$CONTEXT_RENAMED" = "true" ] && [ -n "$KUBECONFIG1_MODIFIED" ] && [ -f "$KUBECONFIG1_MODIFIED" ]; then
    echo "Cleaning up temporary kubeconfig file..."
    rm -f "$KUBECONFIG1_MODIFIED"
    echo "  ✓ Removed: $KUBECONFIG1_MODIFIED"
    echo ""
fi
