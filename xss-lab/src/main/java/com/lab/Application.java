package com.lab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/*
<script>window.location='https://example.com'</script>
<script>document.body.innerHTML='<img src="https://thumb.wikimedia.org/wikipedia/commons/thumb/0/0b/Cat_poster_1.jpg/1920px-Cat_poster_1.jpg?utm_source=ru.wikipedia.org&utm_campaign=imageinfo&utm_content=thumbnail" style="width:100%">'</script>
*/

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
