import requests
#st = 'London'
st = str(input())

params = {
    'q': st,
    'limit': '5',
    'units': 'metric',
    'appid': '682f5e28353d4726dcfdcf3fe4facd95'
}

url = 'http://api.openweathermap.org/geo/1.0/direct'

response = requests.get(url, params=params)

if response.status_code == 200:
    data = response.json()
    lat = data[0]['lat']
    lon = data[0]['lon']
    print('lat = ', lat)
    print('lon = ', lon)
    
else:
    print('Ошибка:', response.status_code)

url2 = 'https://api.openweathermap.org/data/2.5/weather'

#print(data[0])

params = {
    'q': st,
    'lat': lat,
    'lon': lon,
    'lang': 'ru',
    'units': 'metric',
    'appid': '682f5e28353d4726dcfdcf3fe4facd95'
}

response2 = requests.get('https://api.openweathermap.org/data/2.5/weather', params=params)

if response2.status_code == 200:
    data2 = response2.json()
    print('Текущая температура: ', data2['main']['temp'])
    print('Описание погоды: ', data2['weather'][0]['description'])
else:
    print('Ошибка:', response.status_code)


