package auth
//
//import (
//	"context"
//	"github.com/dgrijalva/jwt-go"
//	"github.com/jokermario/monitri/internal/test"
//	"github.com/stretchr/testify/assert"
//	"net/http"
//	"testing"
//)
//
//func TestCurrentUser(t *testing.T) {
//	ctx := context.Background()
//	assert.Nil(t, CurrentAccount(ctx))
//	ctx = WithUser(ctx, "100", "test", "")
//	identity := CurrentAccount(ctx)
//	if assert.NotNil(t, identity) {
//		assert.Equal(t, "100", identity.GetID())
//		//assert.Equal(t, "test", identity.GetName())
//	}
//}
//
//func TestHandler(t *testing.T) {
//	assert.NotNil(t, Handler("test"))
//}
//
//func Test_handleToken(t *testing.T) {
//	req, _ := http.NewRequest("GET", "http://example.com", nil)
//	ctx, _ := test.MockRoutingContext(req)
//	assert.Nil(t, CurrentAccount(ctx.Request.Context()))
//
//	err := handleToken(ctx, &jwt.Token{
//		Claims: jwt.MapClaims{
//			"id":   "100",
//			"name": "test",
//		},
//	})
//	assert.Nil(t, err)
//	identity := CurrentAccount(ctx.Request.Context())
//	if assert.NotNil(t, identity) {
//		assert.Equal(t, "100", identity.GetID())
//		//assert.Equal(t, "test", identity.GetName())
//	}
//}
//
//func TestMocks(t *testing.T) {
//	req, _ := http.NewRequest("GET", "http://example.com", nil)
//	ctx, _ := test.MockRoutingContext(req)
//	assert.NotNil(t, MockAuthHandler(ctx))
//	req.Header = MockAuthHeader()
//	ctx, _ = test.MockRoutingContext(req)
//	assert.Nil(t, MockAuthHandler(ctx))
//	assert.NotNil(t, CurrentAccount(ctx.Request.Context()))
//}
