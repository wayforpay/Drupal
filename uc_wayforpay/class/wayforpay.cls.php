<?php

class Wayforpay
{
  const ORDER_APPROVED = 'Approved';

  const ORDER_SEPARATOR = '#';

  const SIGNATURE_SEPARATOR = ';';

  const URL = "https://secure.wayforpay.com/pay/";
  protected $keysForResponseSignature = array(
    'merchantAccount',
    'orderReference',
    'amount',
    'currency',
    'authCode',
    'cardPan',
    'transactionStatus',
    'reasonCode'
  );

  /** @var array */
  protected $keysForSignature = array(
    'merchantAccount',
    'merchantDomainName',
    'orderReference',
    'orderDate',
    'amount',
    'currency',
    'productName',
    'productCount',
    'productPrice'
  );


  /**
   * @param $option
   * @param $keys
   * @return string
   */
  public function getSignature($option, $keys)
  {
    $hash = array();
    foreach ($keys as $dataKey) {
      if (!isset($option[$dataKey])) {
        continue;
      }
      if (is_array($option[$dataKey])) {
        foreach ($option[$dataKey] as $v) {
          $hash[] = $v;
        }
      } else {
        $hash [] = $option[$dataKey];
      }
    }

    $hash = implode(self::SIGNATURE_SEPARATOR, $hash);
    return hash_hmac('md5', $hash, $this->getSecretKey());
  }


  /**
   * @param $options
   * @return string
   */
  public function getRequestSignature($options)
  {
    return $this->getSignature($options, $this->keysForSignature);
  }

  /**
   * @param $options
   * @return string
   */
  public function getResponseSignature($options)
  {
    return $this->getSignature($options, $this->keysForResponseSignature);
  }


  /**
   * @param array $data
   * @return string
   */
  public function getAnswerToGateWay($data)
  {
    $time = time();
    $responseToGateway = array(
      'orderReference' => $data['orderReference'],
      'status' => 'accept',
      'time' => $time
    );
    $sign = array();
    foreach ($responseToGateway as $dataKey => $dataValue) {
      $sign [] = $dataValue;
    }
    $sign = implode(self::SIGNATURE_SEPARATOR, $sign);
    $sign = hash_hmac('md5', $sign, $this->getSecretKey());
    $responseToGateway['signature'] = $sign;

    return json_encode($responseToGateway);
  }

  /**
   * @param $response
   * @return bool|string
   */
  public function isPaymentValid($response)
  {

    if (!isset($response['merchantSignature']) && isset($response['reason'])) {
      return $response['reason'];
    }
    $sign = $this->getResponseSignature($response);
    if ($sign != $response['merchantSignature']) {
      return 'An error has occurred during payment';
    }

    if ($response['transactionStatus'] == self::ORDER_APPROVED) {
      return true;
    }

    return false;
  }

    public static function _isPaymentValid($wayforpaySettings, $response)
    {
        list($orderId,) = explode(self::ORDER_SEPARATOR, $response['order_id']);
        $order = uc_order_load($orderId);

        if ($order === FALSE || uc_order_status_data($order->order_status, 'state') != 'in_checkout') {
            return t('An error has occurred during payment. Please contact us to ensure your order has submitted.');
        }

        if ($wayforpaySettings->merchant_id != $response['merchant_id']) {
            return t('An error has occurred during payment. Merchant data is incorrect.');
        }

        $originalResponse = $response;
        foreach ($response as $k => $v) {
            if (!in_array($k, self::$responseFields)) {
                unset($response[$k]);
            }
        }

        if (self::getSignature($response, $wayforpaySettings->secret_key) != $originalResponse['signature']) {
            return t('An error has occurred during payment. Signature is not valid.');
        }

        if (drupal_strtolower($originalResponse['sender_email']) !== drupal_strtolower($order->primary_email)) {
            uc_order_comment_save($order->order_id, 0, t('Customer used a different e-mail address during payment: !email', array('!email' => check_plain($originalResponse['sender_email']))), 'admin');
        }

        uc_order_comment_save($order->order_id, 0, "Order status: {$response['order_status']}", 'admin');

        return true;
    }

  protected function getSecretKey()
  {
    $row =  db_select('uc_wayforpay_config', 'ulr')->fields('ulr', array('merchant_id',
      'secret_key',
      'currency',
      'returnUrl',
      'serviceUrl',
      'language'))->execute()->fetchObject();
    return $row->secret_key;
  }
}