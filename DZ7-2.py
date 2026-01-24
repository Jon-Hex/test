import requests
st = 'London'
#st = str(input())
url = 'http://api.openweathermap.org/geo/1.0/direct?q=st&limit=5&appid=682f5e28353d4726dcfdcf3fe4facd95'

response = requests.get(url)

if response.status_code == 200:
    data = response.json()
    lat = data[1]['lat']
    lon = data[1]['lon']
    print(data)
    print('lat = ', lat)
    print('lon = ', lon)
    print(type(lat))
else:
    print('Ошибка:', response.status_code)

url2 = 'https://api.openweathermap.org/data/2.5/weather'

print(data[1])

params = {
    'lat': lat,
    'lon': lon,
    'units': 'metric',
    'appid': '682f5e28353d4726dcfdcf3fe4facd95'
}
response2 = requests.get('https://api.openweathermap.org/data/2.5/weather', params=params)


if response.status_code == 200:
    data2 = response2.json()
    print('data2 ->', data2)
    print('Текущая температура: ', data2['main']['temp'])
    print('Описание погоды: ', data2['weather'][0]['description'])
else:
    print('Ошибка:', response.status_code)