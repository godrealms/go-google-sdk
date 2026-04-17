package onetimeproducts

import (
	"context"

	"google.golang.org/api/androidpublisher/v3"
)

// Service wraps the monetization.onetimeproducts API surface.
type Service struct {
	raw             *androidpublisher.Service
	PurchaseOptions *PurchaseOptionsService
}

func New(raw *androidpublisher.Service) *Service {
	s := &Service{raw: raw}
	s.PurchaseOptions = &PurchaseOptionsService{raw: raw}
	s.PurchaseOptions.Offers = &OffersService{raw: raw}
	return s
}

func (s *Service) Get(ctx context.Context, packageName, productID string) (*androidpublisher.OneTimeProduct, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if productID == "" {
		return nil, ErrMissingProductID
	}
	return s.raw.Monetization.Onetimeproducts.Get(packageName, productID).Context(ctx).Do()
}

func (s *Service) List(ctx context.Context, packageName string, opts ListOptions) (*androidpublisher.ListOneTimeProductsResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	call := s.raw.Monetization.Onetimeproducts.List(packageName).Context(ctx)
	if opts.PageSize > 0 {
		call = call.PageSize(opts.PageSize)
	}
	if opts.PageToken != "" {
		call = call.PageToken(opts.PageToken)
	}
	return call.Do()
}

func (s *Service) Delete(ctx context.Context, packageName, productID string, opts DeleteOptions) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if productID == "" {
		return ErrMissingProductID
	}
	call := s.raw.Monetization.Onetimeproducts.Delete(packageName, productID).Context(ctx)
	if opts.LatencyTolerance != "" {
		call = call.LatencyTolerance(opts.LatencyTolerance)
	}
	return call.Do()
}

func (s *Service) Patch(ctx context.Context, packageName, productID string, product *androidpublisher.OneTimeProduct, opts PatchOptions) (*androidpublisher.OneTimeProduct, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if productID == "" {
		return nil, ErrMissingProductID
	}
	if product == nil {
		return nil, ErrMissingProduct
	}
	call := s.raw.Monetization.Onetimeproducts.Patch(packageName, productID, product).Context(ctx)
	if opts.UpdateMask != "" {
		call = call.UpdateMask(opts.UpdateMask)
	}
	if opts.AllowMissing {
		call = call.AllowMissing(true)
	}
	if opts.LatencyTolerance != "" {
		call = call.LatencyTolerance(opts.LatencyTolerance)
	}
	if opts.RegionsVersion != "" {
		call = call.RegionsVersionVersion(opts.RegionsVersion)
	}
	return call.Do()
}

func (s *Service) BatchGet(ctx context.Context, packageName string, productIDs []string) (*androidpublisher.BatchGetOneTimeProductsResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	return s.raw.Monetization.Onetimeproducts.BatchGet(packageName).ProductIds(productIDs...).Context(ctx).Do()
}

func (s *Service) BatchUpdate(ctx context.Context, packageName string, req *androidpublisher.BatchUpdateOneTimeProductsRequest) (*androidpublisher.BatchUpdateOneTimeProductsResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return s.raw.Monetization.Onetimeproducts.BatchUpdate(packageName, req).Context(ctx).Do()
}

func (s *Service) BatchDelete(ctx context.Context, packageName string, req *androidpublisher.BatchDeleteOneTimeProductsRequest) error {
	if s == nil || s.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if req == nil {
		return ErrMissingRequest
	}
	return s.raw.Monetization.Onetimeproducts.BatchDelete(packageName, req).Context(ctx).Do()
}

// PurchaseOptionsService wraps the onetimeproducts.purchaseOptions sub-resource.
type PurchaseOptionsService struct {
	raw    *androidpublisher.Service
	Offers *OffersService
}

func (p *PurchaseOptionsService) BatchDelete(ctx context.Context, packageName, productID string, req *androidpublisher.BatchDeletePurchaseOptionsRequest) error {
	if p == nil || p.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if productID == "" {
		return ErrMissingProductID
	}
	if req == nil {
		return ErrMissingRequest
	}
	return p.raw.Monetization.Onetimeproducts.PurchaseOptions.BatchDelete(packageName, productID, req).Context(ctx).Do()
}

func (p *PurchaseOptionsService) BatchUpdateStates(ctx context.Context, packageName, productID string, req *androidpublisher.BatchUpdatePurchaseOptionStatesRequest) (*androidpublisher.BatchUpdatePurchaseOptionStatesResponse, error) {
	if p == nil || p.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if productID == "" {
		return nil, ErrMissingProductID
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return p.raw.Monetization.Onetimeproducts.PurchaseOptions.BatchUpdateStates(packageName, productID, req).Context(ctx).Do()
}

// OffersService wraps the onetimeproducts.purchaseOptions.offers sub-resource.
type OffersService struct {
	raw *androidpublisher.Service
}

func (o *OffersService) Activate(ctx context.Context, packageName, productID, purchaseOptionID, offerID string, req *androidpublisher.ActivateOneTimeProductOfferRequest) (*androidpublisher.OneTimeProductOffer, error) {
	if err := o.validatePath(packageName, productID, purchaseOptionID, offerID); err != nil {
		return nil, err
	}
	if req == nil {
		req = &androidpublisher.ActivateOneTimeProductOfferRequest{}
	}
	return o.raw.Monetization.Onetimeproducts.PurchaseOptions.Offers.Activate(packageName, productID, purchaseOptionID, offerID, req).Context(ctx).Do()
}

func (o *OffersService) Cancel(ctx context.Context, packageName, productID, purchaseOptionID, offerID string, req *androidpublisher.CancelOneTimeProductOfferRequest) (*androidpublisher.OneTimeProductOffer, error) {
	if err := o.validatePath(packageName, productID, purchaseOptionID, offerID); err != nil {
		return nil, err
	}
	if req == nil {
		req = &androidpublisher.CancelOneTimeProductOfferRequest{}
	}
	return o.raw.Monetization.Onetimeproducts.PurchaseOptions.Offers.Cancel(packageName, productID, purchaseOptionID, offerID, req).Context(ctx).Do()
}

func (o *OffersService) Deactivate(ctx context.Context, packageName, productID, purchaseOptionID, offerID string, req *androidpublisher.DeactivateOneTimeProductOfferRequest) (*androidpublisher.OneTimeProductOffer, error) {
	if err := o.validatePath(packageName, productID, purchaseOptionID, offerID); err != nil {
		return nil, err
	}
	if req == nil {
		req = &androidpublisher.DeactivateOneTimeProductOfferRequest{}
	}
	return o.raw.Monetization.Onetimeproducts.PurchaseOptions.Offers.Deactivate(packageName, productID, purchaseOptionID, offerID, req).Context(ctx).Do()
}

func (o *OffersService) List(ctx context.Context, packageName, productID, purchaseOptionID string, opts ListOptions) (*androidpublisher.ListOneTimeProductOffersResponse, error) {
	if err := o.validateParent(packageName, productID, purchaseOptionID); err != nil {
		return nil, err
	}
	call := o.raw.Monetization.Onetimeproducts.PurchaseOptions.Offers.List(packageName, productID, purchaseOptionID).Context(ctx)
	if opts.PageSize > 0 {
		call = call.PageSize(opts.PageSize)
	}
	if opts.PageToken != "" {
		call = call.PageToken(opts.PageToken)
	}
	return call.Do()
}

func (o *OffersService) BatchGet(ctx context.Context, packageName, productID, purchaseOptionID string, req *androidpublisher.BatchGetOneTimeProductOffersRequest) (*androidpublisher.BatchGetOneTimeProductOffersResponse, error) {
	if err := o.validateParent(packageName, productID, purchaseOptionID); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return o.raw.Monetization.Onetimeproducts.PurchaseOptions.Offers.BatchGet(packageName, productID, purchaseOptionID, req).Context(ctx).Do()
}

func (o *OffersService) BatchUpdate(ctx context.Context, packageName, productID, purchaseOptionID string, req *androidpublisher.BatchUpdateOneTimeProductOffersRequest) (*androidpublisher.BatchUpdateOneTimeProductOffersResponse, error) {
	if err := o.validateParent(packageName, productID, purchaseOptionID); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return o.raw.Monetization.Onetimeproducts.PurchaseOptions.Offers.BatchUpdate(packageName, productID, purchaseOptionID, req).Context(ctx).Do()
}

func (o *OffersService) BatchDelete(ctx context.Context, packageName, productID, purchaseOptionID string, req *androidpublisher.BatchDeleteOneTimeProductOffersRequest) error {
	if err := o.validateParent(packageName, productID, purchaseOptionID); err != nil {
		return err
	}
	if req == nil {
		return ErrMissingRequest
	}
	return o.raw.Monetization.Onetimeproducts.PurchaseOptions.Offers.BatchDelete(packageName, productID, purchaseOptionID, req).Context(ctx).Do()
}

func (o *OffersService) BatchUpdateStates(ctx context.Context, packageName, productID, purchaseOptionID string, req *androidpublisher.BatchUpdateOneTimeProductOfferStatesRequest) (*androidpublisher.BatchUpdateOneTimeProductOfferStatesResponse, error) {
	if err := o.validateParent(packageName, productID, purchaseOptionID); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return o.raw.Monetization.Onetimeproducts.PurchaseOptions.Offers.BatchUpdateStates(packageName, productID, purchaseOptionID, req).Context(ctx).Do()
}

func (o *OffersService) validateParent(packageName, productID, purchaseOptionID string) error {
	if o == nil || o.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if productID == "" {
		return ErrMissingProductID
	}
	if purchaseOptionID == "" {
		return ErrMissingPurchaseOptionID
	}
	return nil
}

func (o *OffersService) validatePath(packageName, productID, purchaseOptionID, offerID string) error {
	if err := o.validateParent(packageName, productID, purchaseOptionID); err != nil {
		return err
	}
	if offerID == "" {
		return ErrMissingOfferID
	}
	return nil
}
