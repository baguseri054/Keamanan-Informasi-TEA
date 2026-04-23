from flask import Flask, render_template, request

# Initialize the Flask application
app = Flask(__name__)

# Keep your original home page just in case!
@app.route('/')
def home():
    return render_template('index.html')

# --- NEW CODE BELOW ---
# The methods=['GET', 'POST'] allows this route to both SEND the form and RECEIVE data
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If the user clicked "Submit", the request method becomes 'POST'
    if request.method == 'POST':
        # Grab the text they typed into the 'username' box
        name = request.form['username']
        # Return a personalized greeting directly to the screen
        return f"Hello {name}, your POST request was received successfully!"
    
    # If they just visited the page normally (a 'GET' request), show them the form
    return render_template('name.html')

# Run the application
if __name__ == '__main__':
    app.run(debug=True)