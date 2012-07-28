
class Cache(object):
	def __init__(self, max=2500):
		self.d = {}
		self.l = []
		self.max = max

	def put(self, k, v):
		self.d[k] = v
		self.l.append(k)

		while (len(self.l) > self.max):
			kdel = self.l[0]
			del self.l[0]
			del self.d[kdel]

	def get(self, k):
		try:
			return self.d[k]
		except:
			return None

