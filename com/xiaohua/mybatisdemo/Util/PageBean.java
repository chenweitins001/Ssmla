package com.xiaohua.mybatisdemo.Util;

import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;


public class PageBean {

	/**
	 * 页码
	 */
	private int page = 1;

	/**
	 * 每页显示的记录数
	 */
	private int rows = 10;

	/**
	 * 总记录数
	 */
	private int total = 0;


	/**
	 * 是否分页
	 */
	private boolean pagination = true;

	/**
	 * 分页查询url
	 */
	private String url;


	/**
	 * 存放请求参数，用于生成隐藏域中的元素
	 */
	private Map<String,String[]> parameterMap;

	public Map<String, String[]> getParameterMap() {
		return parameterMap;
	}

	public void setParameterMap(Map<String, String[]> parameterMap) {
		this.parameterMap = parameterMap;
	}

	public String getUrl() {
		return url;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	/**
	 * 设置分页公共参数
	 * @return
	 */
	public void setRequest(HttpServletRequest request) {
		if(!StringUtils.isEmpty(request.getParameter("page"))) {
			this.setPage(Integer.valueOf(request.getParameter("page")));
		}
		if(!StringUtils.isEmpty(request.getParameter("rows"))) {
			this.setRows(Integer.valueOf(request.getParameter("rows")));
		}
		if(!StringUtils.isEmpty(request.getParameter("pagination"))) {
			this.setPagination(Boolean.valueOf(request.getParameter("pagination")));
		}
		this.url = request.getRequestURI();
		Map<String,String[]> mm = request.getParameterMap();
		this.parameterMap = request.getParameterMap();
	}

	public int getPage() {
		return page;
	}

	public void setPage(int page) {
		this.page = page;
	}

	public int getRows() {
		return rows;
	}

	public void setRows(int rows) {
		this.rows = rows;
	}

	public int getTotal() {
		return total;
	}

	public void setTotal(int total) {
		this.total = total;
	}

	//计算页数据下标
	public int getStartIndex() {
		return (this.page - 1) * this.rows;
	}

	public boolean isPagination() {
		return pagination;
	}

	public void setPagination(boolean pagination) {
		this.pagination = pagination;
	}

	//获取总页数
	public int getTotalPageNum() {
		if(this.getTotal() % this.rows == 0) {
			return this.getTotal() / this.rows;
		} else {
			return this.getTotal() / this.rows + 1;
		}
	}

	//获取上一页
	public int getPreviousPageNum() {
		return this.page - 1  > 0 ? this.page - 1 : this.page;
	}

	//获取下一页
	public int getNextPageNum() {
		return this.page + 1 < this.getTotalPageNum() ? this.page +	1 : this.getTotalPageNum();
	}

	@Override
	public String toString() {
		return "PageBean [page=" + page + ", rows=" + rows + ", total=" + total + ", pagination=" + pagination + "]";
	}

}
