import socket

def reverse_resolve_hostname() -> str:
    try:
        return socket.gethostbyaddr("10.0.0.2")[0]
    except:
        "You probably need to set up '10.99.0.1' in servername in /etc/hosts"
        raise

print(reverse_resolve_hostname())