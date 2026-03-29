from django.test import TestCase

# NetworkIDS tests
class NetworkIDSBasicTest(TestCase):
    def test_index_page_loads(self):
        response = self.client.get('/networkids/')
        self.assertEqual(response.status_code, 200)
