package com.xiuye.cert.bean;

import lombok.Data;

import java.util.Date;

/**
 * keystore 信息
 */
@Data
public class KeyStoreInfo {
	/**
	 * 证书别名
	 */
	private String alias;
	/**
	 * 存储密钥
	 */
	private String keyStorePwd;
	/**
	 * 证书密码
	 */
	private String certPwd;
	/**
	 * 您的名字与姓氏
	 */
	private String name;
	/**
	 *组织单位名称
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
	 *  您所在的省/市/自治区名称
	 */
	private String province;
	/**
	 *  该单位的双字母国家/地区代码
	 */
	private String country;
	/**
	 * 开始时间
	 */
	private Date startTime;
	/**
	 * 有效日期
	 */
	private long validityDays;
	/**
	 * 文件路径(包括名称)
	 */
	private String pathAndFileName;
	/**
	 *
	 * @param alias 别名
	 * @param keyStorePwd key密码
	 * @param certPwd 证书密码
	 * @param name 签发人名称
	 * @param orgUnit 组织单位名称
	 * @param org 组织名称
	 * @param location 位置名称
	 * @param province 省份名称
	 * @param country 国家code
	 * @param startTime 开始时间
	 * @param validityDays 有效时间
	 * @param pathAndFileName 生成的文件路径
	 */
	public KeyStoreInfo(String alias, String keyStorePwd, String certPwd, String name, String orgUnit, String org, String location, String province, String country, Date startTime, long validityDays, String pathAndFileName) {
		this.alias = alias;
		this.keyStorePwd = keyStorePwd;
		this.certPwd = certPwd;
		this.name = name;
		this.orgUnit = orgUnit;
		this.org = org;
		this.location = location;
		this.province = province;
		this.country = country;
		this.startTime = startTime;
		this.validityDays = validityDays;
		this.pathAndFileName = pathAndFileName;
	}

	public KeyStoreInfo() {
	}

}
