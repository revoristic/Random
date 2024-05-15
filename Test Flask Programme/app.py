from flask import Flask # Basic Webpage

app = Flask(__name__)

@app.route('/')
def home():
    return " Hi my name is Sivasubramaniam!"


if(__name__) =='__main__':
    app.run(debug=True)

