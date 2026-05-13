from scapy.all import sniff, IP
LISTA_NEGRA = ["192.168.1.50", "10.0.0.99"]
def analisar_pacote(pacote):
        if pacote.haslayer(IP):
            ip_origem = pacote[IP].src
            ip_destino = pacote[IP].dst
            if ip_origem in LISTA_NEGRA:
                print(f"⚠️ [BLOQUEADO] Tráfego     barrado de {ip_origem}")
            else:
                print(f"✅ [PERMITIDO] Conexão segura: {ip_origem}")
sniff(prn=analisar_pacote, store=0)
