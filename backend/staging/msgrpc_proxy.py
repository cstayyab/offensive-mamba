import tornado.ioloop
import maproxy.proxyserver

# HTTPS->HTTP
# ssl_certs={     "certfile":  "./certificate.pem",
#                 "keyfile": "./privatekey.pem" }
# "client_ssl_options=ssl_certs" simply means "listen using SSL"
server = maproxy.proxyserver.ProxyServer("115.186.176.141", 55552)
server.listen(55553)
print("http://115.186.176.141:55553 -> http://115.186.176.141:55552")
tornado.ioloop.IOLoop.instance().start()