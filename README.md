##***LibUA Fully converted to .NET Framework 4.8 and fully compatible with LabView 32-Bits 2018.***
This DLL can Write, Read, Start and Stop an OpcUA Server. Methods has been made as simple as possible.
This Repo contain an exemple VI executable on LabView 2018 32-Bits.
To use this lib, you first have to compile the project and place libUA.dll and all its dependencies in the same folder. You'll also need to create a .ini file where you need to declare all your nodes and also their type, id etc ...
##***Your Ini File should look like this***
##[Node1]
##NodeId = 2
##Name = Cmde0
##Type = String
##DefVal = commande0
##
##[Node2]
##NodeId = 3
##Name = Cmde1
##Type = String
##DefVal = commande1
##
##[Node3]
##NodeId = 4
##Name = X
##Type = Float
##DefVal = commandeX

