package com.xiaohua.mybatisdemo.Util;

import net.sourceforge.pinyin4j.PinyinHelper;

import java.util.regex.Pattern;

/**
 * 拼音工具类，能将汉字转换成拼音的首字母
 */
public class PinYinUtil {
	/* 用于中文判断的正则表达式 */
	private static final String regexStr = "[\u4e00-\u9fa5]";

	/**
	 * 将一个字符串中的汉字转换成拼音首字母、非汉字则不变
	 *
	 * @param cn
	 *            String
	 * @return String
	 */
	public static String toPinyin(String cn) {
		String pinyin = null;
		if (null == cn || 0 == cn.trim().length()) {
			return pinyin;
		}

		/* 去掉字符串前后的空格 */
		cn = cn.trim();
		char[] chineseCharacterArr = cn.toCharArray(); // 转换成汉字字符数组
		char[] letteCharacterArr = new char[chineseCharacterArr.length]; // 字母字符数组
		for (int i = 0; i < chineseCharacterArr.length; i++) {
			// 得到汉字拼音的首字母
			letteCharacterArr[i] = getFirstLetterFromPinyin(chineseCharacterArr[i]);
		}

		if (0 != letteCharacterArr.length) {
			pinyin = new String(letteCharacterArr);
			pinyin = pinyin.toUpperCase();
		}
		return pinyin;
	}

	/* 得到一个汉字的拼音的首字母 */
	private static char getFirstLetterFromPinyin(char cn) {
		// 判断cn是否为一个合法的汉字,不是则直接返回cn
		if (!isChineseCharacters(cn)) {
			return cn;
		}

		String[] pyArr = PinyinHelper.toHanyuPinyinStringArray(cn);
		char py = pyArr[0].charAt(0);
		return py;
	}

	/**
	 * 判断字符是否为一个汉字
	 *
	 * @param cn
	 *            char
	 * @return boolean
	 */
	public static boolean isChineseCharacters(char cn) {
		boolean b = false;
		if (Pattern.matches(regexStr, String.valueOf(cn))) {
			b = true;
		}
		return b;
	}

	public static void main(String[] args) {
		String s = "保存并加入A题库";
		System.out.println(PinYinUtil.toPinyin(s).toLowerCase());
	}

}