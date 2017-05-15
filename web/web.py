import flask
app = flask.Flask(__name__, template_folder='templates')

UPLOAD_FOLDER = '/path/to/the/uploads'

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if flask.request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in flask.request.files:
            flash('No file part')
            return flask.redirect(request.url)
        file = flask.request.files['file']
        # TODO: parse data and draw
        return file.read()

    return flask.render_template('upload.html')

@app.route('/chart')
def chart():
    labels = ["January","February","March","April","May","June","July","August"]
    values = [10,9,8,7,6,4,7,8]
    return flask.render_template('chart.html', values=values, labels=labels)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
