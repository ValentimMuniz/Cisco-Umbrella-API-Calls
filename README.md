# Cisco Umbrella API Calls

Desenvolvido por: Valentim Uliana

Essa aplicação tem como intuito facilitar os cadastros em massa de Internal Domains, Internal Networks e Sites do Cisco Umbrella, pois faz o uso de arquivos CSV para envio!
Alguns modelos de CSV estão nesse repositório, mas segue algumas informações:

1. O CSV deve ser em formato serparado por vírgula!!<br>
2. O CSV de Internal Networks deve ser preenchido da seguinte forma:<br>
   <b>Nome,IP,Prefixo</b>
3. Pasta raiz da aplicação fica em C:/uses/USERNAME/.umbrella_api_calls
# Features
A aplicação vai trabalhar de modo inteligente fazendo todas as verificações e logando tudo para a pasta de logs! Entre as verificações estão:
1. Se o CSV de Internal Networks foi preenchido corretamente, <b>como citado acima</b> a aplicação vai te informar que está incorreto e vai gerar um arquivo de log 
