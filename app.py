from os import terminal_size
from storeData import dbmanager
from flask_table import Table, Col, LinkCol
from flask import Flask
from managedb import databaseManager


app = Flask(__name__)

class ItemTable(Table):
    CPEID = Col('CPEID')
    CVEID = LinkCol('CVEID','single_item',url_kwargs=dict(CVEID='CVEID'),attr ='CVEID')



@app.route('/')
def index():
    dbmanager = databaseManager()
    rows = dbmanager.getCPE()
    table = ItemTable(rows)

    # You would usually want to pass this out to a template with
    # render_template.
    return table.__html__()

@app.route('/item/<string:CVEID>')
def single_item(CVEID):
    rows = dbmanager.getCVEData(CVEID)
    print(rows)
    # Similarly, normally you would use render_template
    return '<h1>{}</h1><p>{}</p><hr><small>data: {}</small>'.format(
        rows['cveID'], rows['description'], rows['publishedDate'])

if __name__ == '__main__':
    app.run(debug=True)