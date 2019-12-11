package com.xiaohua.mybatisdemo.Util;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * 中文乱码处理
 * 
 */
public class EncodingFiter implements Filter {

	private String encoding = "UTF-8";// 默认字符集

	public EncodingFiter() {
		super();
	}

	public void destroy() {
	}

	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		String method = request.getMethod();
		if (method.equalsIgnoreCase("get")) {
			Map<String, String[]> map = (Map<String, String[]>) request.getParameterMap();// 保存所有参数名=参数值(数组)的Map集合
			for (String[] values : map.values()) {
				for (int i = 0; i < values.length; i++) {
					values[i] = new String(values[i].getBytes("ISO-8859-1"), this.encoding);
				}
			}
		} else if (method.equalsIgnoreCase("post")) {
			request.setCharacterEncoding(this.encoding);
		}
		response.setContentType("text/html;charset=" + this.encoding);

		chain.doFilter(servletRequest, servletResponse);
	}

	public void init(FilterConfig filterConfig) throws ServletException {
		String s = filterConfig.getInitParameter("encoding");// 读取web.xml文件中配置的字符集
		if (null != s && !s.trim().equals("")) {
			this.encoding = s.trim();
		}
	}

}
