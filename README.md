# PyHashRarExtraction

Кроссплатформенный скрипт на Python 3 для извлечения хэшей из защищённых паролем Rar архивов версии 3, 4, 5, а так же самораспаковывающихся SFX архивов. Извлеченный из архива хэш можно использовать для дальнейшего подбора пароля в [Hashcat](https://hashcat.net/hashcat/).
<br>
# Установка и запуск
``` 
git clone https://github.com/kholodovvv/PyHashRarExtraction.git

cd PyHashRarExtraction

python PyHashRarExtraction.py [параметры]
``` 
<br>
Для запуска скрипта нет необходимости в установке каких либо дополнительных библиотек.
<br>

# Параметры запуска скрипта

```
> Извлечь хэш из архива и вывести его в консоль (Путь должен включать имя файла и расширение)
> Пример: python PyHashRarExtraction.py /home/user/rarFile.rar

python PyHashRarExtraction.py Путь_До_Rar_Архива

> Извлечь хэш из архива и записать его в файл (Путь не должен содержать имени файла)
> Пример: python PyHashRarExtraction.py /home/user/rarFile.rar /home/user/ 

python PyHashRarExtraction.py Путь_До_Rar_Архива Путь_Для_Записи_Файла

Вызов справки
python PyHashRarExtraction.py -h
```