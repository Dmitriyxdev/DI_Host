from livereload import Server
from app import app  # импорт твоего Flask-приложения

if __name__ == "__main__":
    server = Server(app.wsgi_app)
    server.watch("templates/*.html")
    server.watch("static/css/*.css")
    server.watch("static/js/*.js")
    server.serve(host="0.0.0.0", port=5001, debug=True)
