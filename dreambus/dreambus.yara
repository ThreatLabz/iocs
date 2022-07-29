rule dreambus_module
{
  strings:
    $ = "/tmp/.X11-unix/22"
    $ = "172.16.0.0/12"
    $ = "192.168.0.0/16"
    $ = "10.0.0.0/8"
  condition:
    all of them
}


rule dreambus_main
{
  strings:
    $ = "/tmp/.X11-unix/01"
    $ = "/dev/null"
    $ = {2D 63 00 2F 62 69 6E 2F 73 68 00}
    $ = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  condition:
    all of them
}
