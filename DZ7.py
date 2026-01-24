import requests

url1 = 'https://jsonplaceholder.typicode.com/posts/'
i = 1
#url2 = url1 + str(i)

#response = requests.get(url2)

while i <= 5:
    print(i)
    url2 = url1 + str(i)
    response = requests.get(url2)
    if response.status_code == 200:
        data = response.json()
        #data = response.text()
        #print(data)
        print('Заголовок: ', data['title'])
        print('Тело: ', data['body'])
    else:
        print('Ошибка:', response.status_code)
    i += 1
    
    