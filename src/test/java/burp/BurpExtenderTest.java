package burp;

import com.github.nscuro.bradamsang.BradamsaNgExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class BurpExtenderTest {

    @Mock
    private IBurpExtenderCallbacks extenderCallbacksMock;

    @Mock
    private BradamsaNgExtension bradamsaNgExtensionMock;

    private BurpExtender burpExtender;

    @BeforeEach
    void beforeEach() {
        burpExtender = new BurpExtender(bradamsaNgExtensionMock);
    }

    @Test
    void shouldRegisterExtension() {
        burpExtender.registerExtenderCallbacks(extenderCallbacksMock);

        verify(bradamsaNgExtensionMock).registerExtension(extenderCallbacksMock);
    }

}