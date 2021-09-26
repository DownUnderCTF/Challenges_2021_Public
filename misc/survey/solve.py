from requests import get

r = get('https://docs.google.com/forms/d/e/1FAIpQLScrDYkiCSw9eO51HaFaTTXZodtkMzn9TE_Wi9JgEj1kklNJsA/viewform').text
r = r[r.index('DUCTF{'):]
flag = r[:r.index('}')+1]
print(flag)
