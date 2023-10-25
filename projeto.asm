;Carlos Rafael Torres Miranda Novack
.686
.model flat, stdcall
option casemap :none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\masm32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\masm32.lib

.data
    ;parte do output
    outputBemVindo db "Bem vindo ao programa", 0ah, "O que deseja fazer?", 0ah, "1 - Criptografar", 0ah, "2 - Descriptografar", 0ah, "3 - Sair", 0ah, 0h
    outputArqEntrada db "Insira o nome do arquivo para ser lido", 0ah, 0h
    outputArqSaida db "Insira o nome do arquivo para ser escrito", 0ah, 0h
    outputChave db "Insira a chave para ser usada", 0ah, 0h
    outputHandle dd 0

    ;parte do input
    inputOpcao db 50 dup(0)
    inputArqEntrada db 50 dup(0)
    inputArqSaida db 50 dup(0)
    inputChave db 50 dup(0)
    inputHandle dd 0

    fileBuffer db 512 dup(0)
    bufferSize dd 0
    readHandle dd 0
    writeHandle dd 0
    readCount dd 0
    writeCount dd 0
    console_count dd 0

.code

logicaCriptografia:
    ;prólogo da função
    push ebp
    mov ebp, esp
    sub esp, 12 ;usei o valor 12 para reservar 4 bytes para cada um dos parâmetros

    ;pega o endereço do buffer no parametro e copia para a variável local
    mov eax, DWORD PTR [ebp+16]
    mov DWORD PTR [ebp-4], eax
    ;pega o tamanho do buffer no parametro e copia para a variável local
    mov eax, DWORD PTR [ebp+12]
    mov DWORD PTR [ebp-8], eax
    ;pega a chave no parametro e copia para a variável local
    mov eax, DWORD PTR [ebp+8]
    mov DWORD PTR [ebp-12], eax

    comecaCrip:
        xor ebx, ebx
        mov esi, [ebp-4] ;armazena apontador da string em esi

            forCriptografia:
                xor eax, eax ;zera o valor de eax
                mov al, BYTE PTR [ebp-12] ;guarda a chave nos bits menos significativos de eax
                add [esi + ebx],  eax ;soma a chave com o caractere atual que está sendo lido
                inc ebx ;aponta para o proximo caractere do buffer
                cmp ebx, DWORD PTR [ebp-8] ;compara o indice do caractere que está sendo lido com o tamanho do buffer
                jl forCriptografia
            invoke WriteFile, writeHandle, [ebp-4], [ebp-8], addr writeCount, NULL ;escreve no arquivo a string criptografada

    ;epílogo da função
    mov esp, ebp
    pop ebp
    ret 12

logicaDescriptografia:
    ;prólogo da função
    push ebp
    mov ebp, esp
    sub esp, 12 ;usei o valor 12 para reservar 4 bytes para cada um dos parâmetros

    ;pega o endereço do buffer no parametro e copia para a variável local
    mov eax, DWORD PTR [ebp+16]
    mov DWORD PTR [ebp-4], eax
    ;pega o tamanho do buffer no parametro e copia para a variável local
    mov eax, DWORD PTR [ebp+12]
    mov DWORD PTR [ebp-8], eax
    ;pega a chave no parametro e copia para a variável local
    mov eax, DWORD PTR [ebp+8]
    mov DWORD PTR [ebp-12], eax

    comecaDescrip:
        xor ebx, ebx
        mov esi, [ebp-4] ;armazena apontador da string em esi

            forDescriptografia:
                xor eax, eax ;zera o valor de eax
                mov al, BYTE PTR [ebp-12] ;guarda a chave nos bits menos significativos de eax
                sub [esi + ebx],  eax ;subtrai a chave com o caractere atual que está sendo lido
                inc ebx ;aponta para o proximo caractere do buffer
                cmp ebx, DWORD PTR [ebp-8] ;compara o indice do caractere que está sendo lido com o tamanho do buffer
                jl forDescriptografia

            invoke WriteFile, writeHandle, addr fileBuffer, bufferSize, addr writeCount, NULL ;escreve mo arquivo a string descriptografada

    ;epílogo da função
    mov esp, ebp
    pop ebp
    ret 12
    
start:
    inicio:
        ;printar no console a mensagem de inicio do programa
        invoke GetStdHandle, STD_OUTPUT_HANDLE
        mov outputHandle, eax
        invoke WriteConsole, outputHandle, addr outputBemVindo, sizeof outputBemVindo, addr console_count, NULL

        ;ler a escolha do usuário
        invoke GetStdHandle, STD_INPUT_HANDLE
        mov inputHandle, eax
        invoke ReadConsole, inputHandle, addr inputOpcao, sizeof inputOpcao, addr console_count, NULL

        ;trata a string da opção e transforma em ASCII
        mov esi, offset inputOpcao ;armazena apontador da string em esi
        prxCaractereOpcao:
            mov al, [esi] ;move o caractere atual para al
            inc esi ;aponta para o proximo caractere
            cmp al, 13 ;verifica se o caractere eh o ASCII CR - FINALIZAR
            jne prxCaractereOpcao
            dec esi ;aponta para o caractere anterior, onde o CR foi encontrado
            xor al, al ;ASCII 0, terminador de string
            mov [esi], al ;insere ASCII 0 no lugar do ASCII CR
        invoke atodw, offset inputOpcao
        mov inputOpcao, al ;salva o valor tratado de volta em inputOpcao

    ;logica para fazer o que o usuario digitou
    cmp inputOpcao, 2
    ;vai para a parte 1
    jl criptografia
    ;vai para a parte 2
    je descriptografia
    ;vai para a parte 3
    jg sair

    ;Parte 1 - Criptografia    
    criptografia:
        ;pede e lê o nome do arquivo de entrada
        invoke GetStdHandle, STD_OUTPUT_HANDLE
        mov outputHandle, eax
        invoke WriteConsole, outputHandle, addr outputArqEntrada, sizeof outputArqEntrada, addr console_count, NULL
        invoke GetStdHandle, STD_INPUT_HANDLE
        mov inputHandle, eax
        invoke ReadConsole, inputHandle, addr inputArqEntrada, sizeof inputArqEntrada, addr console_count, NULL

        ;trata a string do nome do arquivo de entrada
        mov esi, offset inputArqEntrada ;armazena apontador da string em esi
        prxCaractereArqEntrada_Crip:
            mov al, [esi] ;move o caractere atual para al
            inc esi ;aponta para o proximo caractere
            cmp al, 13 ;verifica se o caractere eh o ASCII CR - FINALIZAR
            jne prxCaractereArqEntrada_Crip
            dec esi ;aponta para o caractere anterior, onde o CR foi encontrado
            xor al, al ;ASCII 0, terminador de string
            mov [esi], al ;insere ASCII 0 no lugar do ASCII CR

        ;pede e lê o nome do arquivo de saida 
        invoke GetStdHandle, STD_OUTPUT_HANDLE
        mov outputHandle, eax
        invoke WriteConsole, outputHandle, addr outputArqSaida, sizeof outputArqSaida, addr console_count, NULL
        invoke GetStdHandle, STD_INPUT_HANDLE
        mov inputHandle, eax
        invoke ReadConsole, inputHandle, addr inputArqSaida, sizeof inputArqSaida, addr console_count, NULL

        ;trata a string do nome do arquivo de saida
        mov esi, offset inputArqSaida ;armazena apontador da string em esi
        prxCaractereArqSaida_Crip:
            mov al, [esi] ;move o caractere atual para al
            inc esi ;aponta para o proximo caractere
            cmp al, 13 ;verifica se o caractere eh o ASCII CR - FINALIZAR
            jne prxCaractereArqSaida_Crip
            dec esi ;aponta para o caractere anterior, onde o CR foi encontrado
            xor al, al ;ASCII 0, terminador de string
            mov [esi], al ;insere ASCII 0 no lugar do ASCII CR

        ;pede e lê a chave
        invoke GetStdHandle, STD_OUTPUT_HANDLE
        mov outputHandle, eax
        invoke WriteConsole, outputHandle, addr outputChave, sizeof outputChave, addr console_count, NULL
        invoke GetStdHandle, STD_INPUT_HANDLE
        mov inputHandle, eax
        invoke ReadConsole, inputHandle, addr inputChave, sizeof inputChave, addr console_count, NULL

        ;trata a string da chave e transforma em ASCII
        mov esi, offset inputChave ;armazena apontador da string em esi
        prxCaractereChave_Crip:
            mov al, [esi] ;move o caractere atual para al
            inc esi ;aponta para o proximo caractere
            cmp al, 13 ;verifica se o caractere eh o ASCII CR - FINALIZAR
            jne prxCaractereChave_Crip
            dec esi ;aponta para o caractere anterior, onde o CR foi encontrado
            xor al, al ;ASCII 0, terminador de string
            mov [esi], al ;insere ASCII 0 no lugar do ASCII CR
        invoke atodw, offset inputChave
        mov inputChave, al ;salva o valor tratado de volta em inputChave
        
        invoke CreateFile, addr inputArqEntrada, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL ;abre o arquivo a ser lido
        mov readHandle, eax

        invoke CreateFile, addr inputArqSaida, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL ;cria o arquivo a ser escrito
        mov writeHandle, eax

        chamaFuncaoCrip:
            invoke ReadFile, readHandle, addr fileBuffer, 512, offset bufferSize, NULL ;lê o arquivo 
            xor eax, eax ;zera o valor de eax
            mov al, inputChave ;salva o valor da chave em eax
        
            lea edx, [fileBuffer] ;passa o endereço de fileBuffer (buffer do arquivo a ser criptografado) para edx
            push edx ;manda edx para a pilha
            push bufferSize ;manda o tamanho do arquivo para a pilha
            push eax ;manda a chave para a pilha
            call logicaCriptografia ;chama a função para realizar a criptografia

            cmp bufferSize, 512 ;verifica se chegou no fim do arquivo
            je chamaFuncaoCrip
        jmp inicio

    ;Parte 2 - Descriptografia
    descriptografia:
        ;pede e lê o nome do arquivo de entrada
        invoke GetStdHandle, STD_OUTPUT_HANDLE
        mov outputHandle, eax
        invoke WriteConsole, outputHandle, addr outputArqEntrada, sizeof outputArqEntrada, addr console_count, NULL
        invoke GetStdHandle, STD_INPUT_HANDLE
        mov inputHandle, eax
        invoke ReadConsole, inputHandle, addr inputArqEntrada, sizeof inputArqEntrada, addr console_count, NULL

        ;trata a string do nome do arquivo de entrada
        mov esi, offset inputArqEntrada ;armazena apontador da string em esi
        prxCaractereArqEntrada_Descrip:
            mov al, [esi] ;move o caractere atual para al
            inc esi ;aponta para o proximo caractere
            cmp al, 13 ;verifica se o caractere eh o ASCII CR - FINALIZAR
            jne prxCaractereArqEntrada_Descrip
            dec esi ;aponta para o caractere anterior, onde o CR foi encontrado
            xor al, al ;ASCII 0, terminador de string
            mov [esi], al ;insere ASCII 0 no lugar do ASCII CR

        ;pede e lê o nome do arquivo de saida 
        invoke GetStdHandle, STD_OUTPUT_HANDLE
        mov outputHandle, eax
        invoke WriteConsole, outputHandle, addr outputArqSaida, sizeof outputArqSaida, addr console_count, NULL
        invoke GetStdHandle, STD_INPUT_HANDLE
        mov inputHandle, eax
        invoke ReadConsole, inputHandle, addr inputArqSaida, sizeof inputArqSaida, addr console_count, NULL

        ;trata a string do nome do arquivo de saida
        mov esi, offset inputArqSaida ;armazena apontador da string em esi
        prxCaractereArqSaida_Descrip:
            mov al, [esi] ;move o caractere atual para al
            inc esi ;aponta para o proximo caractere
            cmp al, 13 ;verifica se o caractere eh o ASCII CR - FINALIZAR
            jne prxCaractereArqSaida_Descrip
            dec esi ;aponta para o caractere anterior, onde o CR foi encontrado
            xor al, al ;ASCII 0, terminador de string
            mov [esi], al ;insere ASCII 0 no lugar do ASCII CR

        ;pede e lê a chave
        invoke GetStdHandle, STD_OUTPUT_HANDLE
        mov outputHandle, eax
        invoke WriteConsole, outputHandle, addr outputChave, sizeof outputChave, addr console_count, NULL
        invoke GetStdHandle, STD_INPUT_HANDLE
        mov inputHandle, eax
        invoke ReadConsole, inputHandle, addr inputChave, sizeof inputChave, addr console_count, NULL

        ;trata a string da chave e transforma em ASCII
        mov esi, offset inputChave ;armazena apontador da string em esi
        prxCaractereChave_Desrip:
            mov al, [esi] ;move o caractere atual para al
            inc esi ;aponta para o proximo caractere
            cmp al, 13 ;verifica se o caractere eh o ASCII CR - FINALIZAR
            jne prxCaractereChave_Desrip
            dec esi ;aponta para o caractere anterior, onde o CR foi encontrado
            xor al, al ;ASCII 0, terminador de string
            mov [esi], al ;insere ASCII 0 no lugar do ASCII CR
        invoke atodw, offset inputChave
        mov inputChave, al ;salva o valor tratado de volta em inputChave

        invoke CreateFile, addr inputArqEntrada, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL ;abre o arquivo a ser lido
        mov readHandle, eax

        invoke CreateFile, addr inputArqSaida, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL ;cria o arquivo a ser escrito
        mov writeHandle, eax

        chamaFuncaoDescriptografia:
            invoke ReadFile, readHandle, addr fileBuffer, 512, offset bufferSize, NULL ;lê o arquivo 
            xor eax, eax ;zera o valor de eax
            mov al, inputChave ;salva o valor da chave em eax

            lea edx, [fileBuffer] ;passa o endereço de fileBuffer (buffer do arquivo a ser criptografado) para edx
            push edx ;manda edx para a pilha
            push bufferSize ;manda o tamanho do arquivo para a pilha
            push eax ;manda a chave para a pilha
            call logicaDescriptografia ;chama a função para realizar a descriptografia

            cmp bufferSize, 512 ;verifica se chegou no fim do arquivo
            je chamaFuncaoDescriptografia
        jmp inicio

    ;Parte 3 - Sair
    sair:
        invoke ExitProcess, 0
end start