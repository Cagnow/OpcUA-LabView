***LibUA Fully converted to .NET Framework 4.8 and compatible with LabView 32-Bits 2018.***</br>
This DLL can Write, Read, Start and Stop an OpcUA Server. Methods has been made as simple as possible.
This Repo contain an exemple VI executable on LabView 2018 32-Bits.
To use this lib, you first have to compile the project and place libUA.dll and all its dependencies in the same folder. You'll also need to create a .ini file where you need to declare all your nodes and also their type, id etc ...</br>
***Your Ini File should look like this***</br>
[Node1]</br>
NodeId = 2</br>
Name = Cmde0</br>
Type = String</br>
DefVal = commande0</br>
</br>
[Node2]</br>
NodeId = 3</br>
Name = Cmde1</br>
Type = String</br>
DefVal = commande1</br>
</br>
[Node3]</br>
NodeId = 4</br>
Name = X</br>
Type = Float</br>
DefVal = commandeX</br>

