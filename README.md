# Build

```
cd cmd/demo/
go build main.go
```

# Use

Work only as NT Authority system (PsExec system before use)

```
c:\> main.exe
```

display all tickets

usage :

```
Usage of kerbegoast.exe:
  -krbtgt
        Display only krbtgt
  -monitor int
        Monitor new ticket

```
# Thanks
Part of this work was made possible thanks to the work of carpeltt (https://github.com/carlpett/winlsa)
