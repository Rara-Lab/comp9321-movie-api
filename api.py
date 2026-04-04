from flask import Flask
from flask_restx import Api,Resource
app = Flask(__name__)
api = Api(
    app,
    version="1.0",
    title="Movie REST API",
    description="COMP9321 Assignment 2 API",
    doc="/"
)
ns = api.namespace("test",description="Test endpoints")

@ns.route("/ping")
class PingResource(Resource):
    def get(self):
        return {"message":"Hello"},250

if __name__=="__main__":
    app.run(debug=True)



