package templates;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable()  // Enable this if CSRF protection is needed
                .authorizeHttpRequests()
                .requestMatchers("/home").permitAll()  // Publicly accessible
                .requestMatchers("/student/**").hasRole("STUDENT")  // Role-based access
                .requestMatchers("/admin").hasRole("ADMIN")
                .anyRequest().authenticated()  // All other requests need authentication
                .and()
                .httpBasic();  // Using basic authentication for simplicity
        return httpSecurity.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.builder()
                .username("mausheen")
                .password(passwordEncoder().encode("mausheen123"))
                .roles("STUDENT")
                .build();

        UserDetails user2 = User.builder()
                .username("Minesh")
                .password(passwordEncoder().encode("minesh123"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user1, user2);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
