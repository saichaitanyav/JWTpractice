package com.security.microservice.JWT.app.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.security.microservice.JWT.app.service.UserService;
import com.security.microservice.JWT.app.utility.JWTUtility;

@Component
public class JwtFilter extends OncePerRequestFilter{
	@Autowired
	private JWTUtility jwtUtility;
	
	@Autowired
	private UserService userService;
	
	@Override
	protected void doFilterInternal(HttpServletRequest httpRequest, HttpServletResponse httpResponse,FilterChain filterchain) throws IOException, ServletException {
		String authorization = httpRequest.getHeader("Authorization");
		String token = null;
		String userName = null;
		if(null != authorization && authorization.startsWith("Bearer ")) {
			token = authorization.substring(7);
			userName = jwtUtility.getUsernameFromToken(token);
		}
		
		if(null != userName && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = userService.loadUserByUsername(userName);
			
			if(jwtUtility.validateToken(token, userDetails)) {
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				
				usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
				
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}
		}
		
		filterchain.doFilter(httpRequest, httpResponse);
		
	}
}
