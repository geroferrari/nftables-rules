import json


with open('output.json', 'r') as f:
    json_data = json.load(f)

print ("{:<10} | {:<21} | {:<21} |".format('Ingress', 'BA_ETH', 'BC_ETH'))
print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('', 'packets', 'Bytes', 'packets', 'Bytes'))
print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('ARP', json_data['nftables'][2]['counter']['packets'] , json_data['nftables'][2]['counter']['bytes'] , json_data['nftables'][11]['counter']['packets'], json_data['nftables'][11]['counter']['bytes'] ))
print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('ICMP', json_data['nftables'][3]['counter']['packets'] , json_data['nftables'][3]['counter']['bytes'],  json_data['nftables'][12]['counter']['packets'], json_data['nftables'][12]['counter']['bytes'] ))
print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('TCP', json_data['nftables'][4]['counter']['packets'] , json_data['nftables'][4]['counter']['bytes'],  json_data['nftables'][13]['counter']['packets'], json_data['nftables'][13]['counter']['bytes'] ))
print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('UDP', json_data['nftables'][5]['counter']['packets'] , json_data['nftables'][5]['counter']['bytes'],  json_data['nftables'][14]['counter']['packets'], json_data['nftables'][14]['counter']['bytes'] ))
print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('IP', json_data['nftables'][6]['counter']['packets'] , json_data['nftables'][6]['counter']['bytes'],  json_data['nftables'][15]['counter']['packets'], json_data['nftables'][15]['counter']['bytes'] ))
print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('IP6', json_data['nftables'][7]['counter']['packets'] , json_data['nftables'][7]['counter']['bytes'],  json_data['nftables'][16]['counter']['packets'], json_data['nftables'][16]['counter']['bytes'] ))
print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('Ethernet', json_data['nftables'][8]['counter']['packets'] , json_data['nftables'][8]['counter']['bytes'],  json_data['nftables'][17]['counter']['packets'], json_data['nftables'][17]['counter']['bytes']))
print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('Dropped PL', json_data['nftables'][9]['counter']['packets'] , json_data['nftables'][9]['counter']['bytes'],  json_data['nftables'][18]['counter']['packets'], json_data['nftables'][18]['counter']['bytes'] ))
print ("{:<10} | {:<10} {:<10} | {:<10} {:<10} |".format('Dropped L', json_data['nftables'][10]['counter']['packets'] , json_data['nftables'][10]['counter']['bytes'],  json_data['nftables'][19]['counter']['packets'], json_data['nftables'][19]['counter']['bytes'] ))
print (":-------------------------------------------------------------:")


with open('ns_c_output.json', 'r') as f:
    json_data = json.load(f)

print ("{:<10} | {:<21} |".format('Ingress', 'CB_ETH'))
print ("{:<10} | {:<10} {:<10} |".format('', 'packets', 'Bytes'))
print ("{:<10} | {:<10} {:<10} |".format('ARP', json_data['nftables'][2]['counter']['packets'] , json_data['nftables'][2]['counter']['bytes']))
print ("{:<10} | {:<10} {:<10} |".format('ICMP', json_data['nftables'][3]['counter']['packets'] , json_data['nftables'][3]['counter']['bytes']))
print ("{:<10} | {:<10} {:<10} |".format('TCP', json_data['nftables'][4]['counter']['packets'] , json_data['nftables'][4]['counter']['bytes']))
print ("{:<10} | {:<10} {:<10} |".format('UDP', json_data['nftables'][5]['counter']['packets'] , json_data['nftables'][5]['counter']['bytes']))
print ("{:<10} | {:<10} {:<10} |".format('IP', json_data['nftables'][6]['counter']['packets'] , json_data['nftables'][6]['counter']['bytes']))
print ("{:<10} | {:<10} {:<10} |".format('IP6', json_data['nftables'][7]['counter']['packets'] , json_data['nftables'][7]['counter']['bytes']))
print ("{:<10} | {:<10} {:<10} |".format('Ethernet', json_data['nftables'][8]['counter']['packets'] , json_data['nftables'][8]['counter']['bytes']))
print ("{:<10} | {:<10} {:<10} |".format('Dropped', json_data['nftables'][9]['counter']['packets'] , json_data['nftables'][9]['counter']['bytes']))
print (":-------------------------------------------------------------:")
