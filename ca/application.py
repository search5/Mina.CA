from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def mina_ca_main():
    return render_template('index.html')
