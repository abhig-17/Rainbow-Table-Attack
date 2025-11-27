from flask import Flask, render_template

# Initialize the Flask application
app = Flask(__name__)

# Move your CSS and JS into a 'static' folder.
# Flask serves static files from a folder named 'static' by default.

# Route for the homepage
@app.route('/')
def index():
    # render_template looks for the file in a folder named 'templates' by default, 
    # but since this is a simple single-page app, we can serve it directly 
    # if it's placed outside the templates folder, or you can use send_file
    # or you can rename 'index.html' to 'index_page.html' and put it in 'templates'

    # Simplest way: Place index.html in a 'templates' folder and use render_template.
    # If index.html is in a 'templates' folder:
    # return render_template('index.html') 

    # For a minimal example serving the provided index.html, we'll assume it's 
    # in a 'templates' folder for standard Flask conventions.
    
    # ***ASSUMPTION: 'index.html' is moved to a new folder named 'templates'***
    return render_template('index.html')


if __name__ == '__main__':
    # Run the application on http://127.0.0.1:5000/
    # In a production environment, you would use a WSGI server like Gunicorn or uWSGI.
    app.run(debug=True)