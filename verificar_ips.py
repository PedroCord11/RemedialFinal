##Desde universidad hasta 9A RIC
##Ya termine 
import ipaddress

def solicitar_datos():
    while True:
        try:
            ip_red = input("Ingrese la dirección IP de red (ejemplo: 192.168.1.0): ")
            prefijo = int(input("Ingrese el prefijo de la máscara de subred (ejemplo: 24): "))
            red = ipaddress.ip_network(f"{ip_red}/{prefijo}", strict=False)
            return red, ip_red
        except ValueError:
            print("Entrada inválida. Por favor, ingrese una dirección IP y un prefijo válidos.")

def verificar_ips(red):
    ip_activas = []
    ip_inactivas = []

    for ip in red.hosts():
        while True:
            estado = input(f"¿La IP {ip} está activa? (1 para activa, 0 para inactiva): ")
            if estado == '1':
                ip_activas.append(str(ip))
                break
            elif estado == '0':
                ip_inactivas.append(str(ip))
                break
            else:
                print("Valor no válido, todas las IPs restantes se marcarán como activas.")
                ip_activas.append(str(ip))
                # Marcar todas las IPs restantes como activas
                for ip_restante in red.hosts():
                    if ip_restante not in ip_activas and ip_restante not in ip_inactivas:
                        ip_activas.append(str(ip_restante))
                return ip_activas, ip_inactivas

    return ip_activas, ip_inactivas

def guardar_ips_activas(ip_activas, ip_red):
    # Reemplaza los puntos de la dirección IP con guiones bajos para el nombre del archivo
    ip_formato_archivo = ip_red.replace('.', '_')
    nombre_archivo = f"IPsActivas{ip_formato_archivo}.txt"
    
    # Guardar las IPs activas en un archivo de texto
    with open(nombre_archivo, 'w') as archivo:
        for ip in ip_activas:
            archivo.write(ip + '\n')
    
    print(f"Direcciones IP activas guardadas en el archivo {nombre_archivo}")

def main():
    red, ip_red = solicitar_datos()
    ip_activas, _ = verificar_ips(red)
    
    print("\nDirecciones IP activas:")
    for ip in ip_activas:
        print(ip)
    
    # Guardar las IPs activas en un archivo
    guardar_ips_activas(ip_activas, ip_red)

if __name__ == "__main__":
    main()
