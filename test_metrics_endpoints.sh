#!/bin/bash
# Test script to verify metrics endpoints are accessible

echo "Testing metrics endpoints..."
echo ""

# cert-manager
echo "=== cert-manager ==="
curl -s --connect-timeout 2 http://cert-manager.cert-manager.svc.cluster.local:9402/metrics | head -5
echo ""

# elasticsearch
echo "=== elasticsearch ==="
curl -s --connect-timeout 2 http://elasticsearch-metrics.elasticsearch.svc.cluster.local:9114/metrics | head -5
echo ""

# gmp-system alertmanager
echo "=== gmp-system alertmanager ==="
curl -s --connect-timeout 2 http://alertmanager.gmp-system.svc.cluster.local:9093/metrics | head -5
echo ""

# grafana
echo "=== grafana ==="
curl -s --connect-timeout 2 http://grafana.grafana.svc.cluster.local:3000/metrics | head -5
echo ""

# apisix-admin
echo "=== apisix-admin ==="
curl -s --connect-timeout 2 http://apisix-admin.ingress-apisix.svc.cluster.local:9180/metrics | head -5
echo ""

# keycloak
echo "=== keycloak ==="
curl -s --connect-timeout 2 http://keycloak-metrics.keycloak.svc.cluster.local:9000/metrics | head -5
echo ""

# metrics-server
echo "=== metrics-server ==="
curl -k -s --connect-timeout 2 https://metrics-server.kube-system.svc.cluster.local:443/metrics | head -5
echo ""

# loki components
echo "=== loki-compactor ==="
curl -s --connect-timeout 2 http://loki-grafana-loki-compactor.loki.svc.cluster.local:3100/metrics | head -5
echo ""

# prometheus
echo "=== prometheus ==="
curl -s --connect-timeout 2 http://prometheus-kube-prometheus-prometheus.prometheus.svc.cluster.local:9090/metrics | head -5
echo ""

# rabbitmq
echo "=== rabbitmq ==="
curl -s --connect-timeout 2 http://rabbitmq.rabbitmq-system.svc.cluster.local:15692/metrics | head -5
echo ""

echo "Done!"
