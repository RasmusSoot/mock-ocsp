# Change working directory so relative paths (and template lookup) work again
import os
os.chdir(os.path.dirname(__file__))

from mock_ocspresponder import app
application = app._app