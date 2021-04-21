from flask import Flask

from myBlog.__init__ import create_app

app = Flask(__name__)

if __name__ == '__main__':
    create_app().run(port=6666, debug=True)
