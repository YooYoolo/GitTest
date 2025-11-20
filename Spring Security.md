## Авторизация (form)

### SecurityFilterChain

#### Example
```
@Bean
public SecurityFilterChain securityFilterChain(HttpScurity http) 
throws Exeption 
{
	return http.
		.authorizeHttpRequest(authorizeHttpRequest -> 
			authorizeHttpRequest.requestMatchers("/some-api/**")
				.hasRole("ADMIN"))
		.csrf(AbstractHttpConfigurer::disable)
		.httpBasic(Customizer.withDefaults())
		.sessionManagement(sessionManagement -> sessionManagement
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
		.build();
}
```

1. authorizeHttpRequest - конфигурация правил доступа.
2. requestMatchers("/some-api/..") - какие url попадают под правило.
3. hasRole("ADMIN") - само правило есть ли роль админа, в базе данных должно быть ROLE_ADMIN, либо использовать .hasAuthority тогда ROLE_ можно не добавлять.
4. csrf(AbstractHttpConfigurer::disable) - отключаем csrf защиту, потому что у нас не куки сессии или формы, при httpBasic + STATELESS запросы идут с заголовком Authorization.
5. httpBasic(Customizer.withDefaults()) - добавляет BasicAuthenticationFilter он смотрит заголовок Authorization создает токен AuthenticationToken и передает AuthorizationManager для проверки.
6. sessionManagement - говорит не сохранять сессию, Spring не создает и не использует httpSession для сохранения в SecurityContext.
#### Последовательность 

	Приходит запрос -> цепочка фильтров (securityFilterChain) перебирает фильтры -> если есть Authorization, BasicAuthenticationFilter пытается аутентифицировать -> AuthenticationManager через провайдеры вызывает UserDetailsService и сверяет пароль -> если совпадает создаётся аутентифицированный Authentication -> проверяются права (hasRole).

### Как клиент аутентифицируется к сервису

```
@Bean
public RestClientProductRestClient productRestClient(      @Value("${yotsume.services.catalogue.uri:http://localhost:8081}") String catalogueBaseUri,
        @Value("${yotsume.services.catalogue.username:}") String catalogueUsername,
        @Value("${yotsume.services.catalogue.password:}") String cataloguePassword)
{
    return new RestClientProductRestClient(RestClient.builder()
            .baseUrl(catalogueBaseUri)
            .requestInterceptor(new BasicAuthenticationInterceptor(
                    catalogueUsername,
                    cataloguePassword))
            .build());
}

```

1. RestClient.builder().baseUrl(...) - задает базовый url к которому будут относиться запросы
2. requestInterceptor(...) - перехватчик для модификации запросов перед отправкой
3. BasicAuthenticationInterceptor - стандартный перехватчик для добавления заголовка Authorization: Basic base64(username:password) к каждому запросу

Код добавляет Authorization хедер отправлят запрос в сервис, там запрос проверятся на соответствие роли и приходит ответ в RestClient.


### YotsUserDetailService.loadUserByUsername(...) — роль и поведение при аутентификации

```
@Override
@Transactional(readOnly = true)
public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return this.yotsUserRepository
            .findByUsername(username)
            .map(user -> User.builder()
                    .username(user.getUsername())
                    .password(user.getPassword())
                    .authorities(user.getAuthorities().stream()
                            .map(Authority::getAuthority)
                            .map(SimpleGrantedAuthority::new)
                            .toList())
                    .build())
            .orElseThrow(() -> new UsernameNotFoundException("User %s not found".formatted(username)));
}
```

1. serDetailsService.loadUserByUsername - стандартный контракт Spring Security. Нужен чтобы получить UserDetails при попытке аутентификации.
2. User.builder()...build() - создает Spring Security User с именем, паролем и ролями

### Полная цепочка: от входящего запроса до проверки доступа (пример Basic auth, stateless)

- Клиент (manager-app RestClient) шлёт HTTP-запрос с `Authorization: Basic ...`.
    
- На catalogue-service Spring Security `BasicAuthenticationFilter` перехватывает запрос.
    
- Фильтр декодирует credentials и создаёт `UsernamePasswordAuthenticationToken` (unauthenticated).
    
- `AuthenticationManager` пробрасывает токен в `DaoAuthenticationProvider`.
    
- `DaoAuthenticationProvider` вызывает `UserDetailsService.loadUserByUsername(username)`.
    
- `YotsUserDetailService` достаёт пользователя и возвращает `UserDetails` (username, encodedPassword, authorities).
    
- `DaoAuthenticationProvider` вызывает `passwordEncoder.matches(rawPassword, encodedPasswordFromDb)`.
    
- Если `matches==true`, провайдер создаёт authenticated `Authentication` и возвращает.
    
- Фильтр поместит Authentication в `SecurityContext` (в stateless это локально на время запроса).
    
- Дальше работают authorization rules: `requestMatchers(...).hasRole("SERVICE")` — Spring сверяет `Authentication.getAuthorities()` и разрешает или запрещает доступ.
    
- Если доступ разрешён — контроллер вызывается и отвечает; если нет — 403.


