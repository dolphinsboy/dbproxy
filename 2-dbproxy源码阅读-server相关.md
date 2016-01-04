###1、init\_signal_handlers（信号量相关）

```c
void init_signal_handlers() {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
}
```

###2、network\_server\_start

```c
int network_server_start(network_server *srv)

```
