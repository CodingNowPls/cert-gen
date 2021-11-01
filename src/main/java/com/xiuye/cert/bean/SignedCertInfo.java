package com.xiuye.cert.bean;

import lombok.Data;

/**
 * 签名证书信息
 */
@Data
public class SignedCertInfo {
	/**
	 * 您的名字与姓氏
	 */
	private String name;
	/**
	 * 组织单位名称
	 */
	private String orgUnit;
	/**
	 * 您的组织名称
	 */
	private String org;
	/**
	 * 您所在的城市或区域名称
	 */
	private String location;
	/**
	 * 您所在的省/市/自治区名称
	 */
	private String province;
	/**
	 * 该单位的双字母国家/地区代码
	 */
	private String country;
	/**
	 * keyStore 路径
	 */
	private String keyStorePath;
	/**
	 * keyStore密码
	 */
	private String keyStorePwd;
	/**
	 *证书颁发者 别名
	 */
	private String issuerAlias;
	/**
	 * 证书颁发者证书密码
	 */
	private String issuerAliasPwd;
	/**
	 *  使用者 证书别名
	 */
	private String subjectAlias;
	/**
	 * 使用者 证书密码
	 */
	private String subjectAliasPwd;
	/**
	 *  有效期,单位:天
	 */
	private int validity;
	/**
	 * 存储签发证书的路径
	 */
	private String subjectPath;
	
}
