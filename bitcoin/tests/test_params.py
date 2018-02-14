from unittest import TestCase

import bitcoin
from bitcoin import GenericParams, MainParams, SelectParams
from bitcoin.core import CoreMainParams


class TestGenericParamsObject(TestCase):

    def tearDown(self):
        SelectParams('mainnet')

    def test_generic_params_object_in_select_params(self):
        self.assertEqual(bitcoin.params.MESSAGE_START, MainParams.MESSAGE_START, b'\xf9\xbe\xb4\xd9')
        self.assertEqual(bitcoin.params.MAX_MONEY, CoreMainParams.MAX_MONEY, 21*10**14)

        params_obj = GenericParams()
        params_obj.MESSAGE_START = b'test'
        params_obj.MAX_MONEY = 1500100900

        SelectParams(name='test', generic_params_object=params_obj)

        self.assertEqual(bitcoin.params.MESSAGE_START, params_obj.MESSAGE_START, b'test')
        self.assertEqual(bitcoin.params.MAX_MONEY, params_obj.MAX_MONEY, 1500100900)
