# icefire_linux1
Al detectar la presencia de estas características, se activará una alerta advirtiendo de un posible acceso por parte de IceFire ransomware.
Esta regla busca la secuencia de bytes del encabezado ELF, el compilador GCC, el comando wget utilizado para descargar las cargas útiles y la extensión ".ifire". 
Además, comprueba que el tamaño del archivo sea 2217728 bytes, que es el tamaño de la versión IceFire Linux descrita en la información proporcionada. 
