# Étapes d'Utilisation

## Démarrer le serveur Web Python 

A l'aide d'un IDE ou d'un terminal avec "python3 Server.py"
Le serveur démarre et écoute sur le port 8080.

## Démarrer le prgramme cible

Par défaut, lancez notepad.exe et laissez le en arrière plan

## Compiler et lancer le loader

Ouvrez le projet dans Visual Studio.
Compilez et lancez le programme.

## Ce que fait le programme :

1. Télécharge le shellcode chiffré depuis le serveur Python.
2. Déchiffre le shellcode avec la clé XOR reçue.
3. Injecte le shellcode dans un processus cible (ici notepad.exe).

Le shellcode par défaut crée une MessageBox affichant "Hello World"

## **Structure du Projet**

|**Fichier/Dossier**|**Description**|
|---|---|
|`main.cpp`|Code source principal du loader.|
|`http_client.cpp`|Download le shellcode depuis le server Python.|
|`chiffrement.cpp`|Déchiffre le shellcode en XOR.|
|`memory_handler.cpp`|rRun le shellcode et libère la mémoire après.|
|`main.py`|Script Python servant le shellcode chiffré.|
|`README.md`|Instructions d'utilisation (ce fichier).|

## **Résumé des Objectifs Réalisés**

|**Objectif**|**Statut**|
|---|---|
|Injection de shellcode dans un processus distant|✅ Réalisé|
|Utilisation exclusive de l'API Windows|✅ Réalisé|
|Pas d'appel à des fonctions comme printf, scanf, malloc, free, strcpy, memcpy|✅ Réalisé|
|Téléchargement du shellcode depuis un serveur Web Python|✅ Réalisé|
|La page mémoire où le shellcode est injectée a les permissions RX|✅ Réalisé|
|README explicatif|✅ Réalisé|
|Pas de Warnings a la compilation|✅ Réalisé|
|Les variables allouées avec LocalAlloc sont libérées|✅ Réalisé|

|**Points Bonus**|**Statut**|
|---|---|
|GetModuleHandle & GetProcAddress Masking|❌ Pas fait|
|Custom GetModuleHandle & GetProcAddress|❌ Pas fait|
|API Hashing|❌ Pas fait|
|---|---|
|RC4 Encryption|❌ Pas fait|
|---|---|
|Random Key on Download|✅ Fait (+2)|
|---|---|
|Injection via PID|❌ Pas fait|
|Injection via Process Name|❌ Pas fait|
|---|---|
|Overwrite Shellcode Buffer with Zeros||
|---|---|
|Use NTDLL Functions|❌ Pas fait|
|---|---|
|Alternative Injection Methods (APC, etc.)|❌ Pas fait|
|---|---|
|Other Relevant Features|❌ Pas fait|
## Informations Complémentaires

* Pour cibler un autre processus que notepad.exe, modifiez le nom du processus dans le code source.
* Attention à la taille de la variable de taille du payload si jamais il y a changement du payload
