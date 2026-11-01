import pandas as pd

data = pd.read_csv("../dataset/phishing_urls.csv")

print(data.head())
print(data.shape)