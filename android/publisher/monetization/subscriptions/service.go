package subscriptions

import (
	"context"

	"google.golang.org/api/androidpublisher/v3"
)

// Service wraps the monetization.subscriptions API surface.
type Service struct {
	raw       *androidpublisher.Service
	BasePlans *BasePlansService
}

func New(raw *androidpublisher.Service) *Service {
	s := &Service{raw: raw}
	s.BasePlans = &BasePlansService{raw: raw}
	s.BasePlans.Offers = &OffersService{raw: raw}
	return s
}

func (s *Service) Get(ctx context.Context, packageName, productID string) (*androidpublisher.Subscription, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if productID == "" {
		return nil, ErrMissingProductID
	}
	return s.raw.Monetization.Subscriptions.Get(packageName, productID).Context(ctx).Do()
}

func (s *Service) List(ctx context.Context, packageName string, opts ListOptions) (*androidpublisher.ListSubscriptionsResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	call := s.raw.Monetization.Subscriptions.List(packageName).Context(ctx)
	if opts.PageSize > 0 {
		call = call.PageSize(opts.PageSize)
	}
	if opts.PageToken != "" {
		call = call.PageToken(opts.PageToken)
	}
	if opts.ShowArchived {
		call = call.ShowArchived(true)
	}
	return call.Do()
}

func (s *Service) Create(ctx context.Context, packageName, productID string, sub *androidpublisher.Subscription, opts CreateOptions) (*androidpublisher.Subscription, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if productID == "" {
		return nil, ErrMissingProductID
	}
	if sub == nil {
		return nil, ErrMissingSubscription
	}
	call := s.raw.Monetization.Subscriptions.Create(packageName, sub).ProductId(productID).Context(ctx)
	if opts.RegionsVersion != "" {
		call = call.RegionsVersionVersion(opts.RegionsVersion)
	}
	return call.Do()
}

func (s *Service) Patch(ctx context.Context, packageName, productID string, sub *androidpublisher.Subscription, opts PatchOptions) (*androidpublisher.Subscription, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if productID == "" {
		return nil, ErrMissingProductID
	}
	if sub == nil {
		return nil, ErrMissingSubscription
	}
	call := s.raw.Monetization.Subscriptions.Patch(packageName, productID, sub).Context(ctx)
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
	_ = opts // DeleteCall currently has no latency param on monetization.subscriptions.
	return s.raw.Monetization.Subscriptions.Delete(packageName, productID).Context(ctx).Do()
}

func (s *Service) Archive(ctx context.Context, packageName, productID string, req *androidpublisher.ArchiveSubscriptionRequest) (*androidpublisher.Subscription, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if productID == "" {
		return nil, ErrMissingProductID
	}
	if req == nil {
		req = &androidpublisher.ArchiveSubscriptionRequest{}
	}
	return s.raw.Monetization.Subscriptions.Archive(packageName, productID, req).Context(ctx).Do()
}

func (s *Service) BatchGet(ctx context.Context, packageName string, productIDs []string) (*androidpublisher.BatchGetSubscriptionsResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	return s.raw.Monetization.Subscriptions.BatchGet(packageName).ProductIds(productIDs...).Context(ctx).Do()
}

func (s *Service) BatchUpdate(ctx context.Context, packageName string, req *androidpublisher.BatchUpdateSubscriptionsRequest) (*androidpublisher.BatchUpdateSubscriptionsResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return s.raw.Monetization.Subscriptions.BatchUpdate(packageName, req).Context(ctx).Do()
}

// ConvertRegionPrices calls the monetization.convertRegionPrices endpoint.
func (s *Service) ConvertRegionPrices(ctx context.Context, packageName string, req *androidpublisher.ConvertRegionPricesRequest) (*androidpublisher.ConvertRegionPricesResponse, error) {
	if s == nil || s.raw == nil {
		return nil, ErrServiceNil
	}
	if packageName == "" {
		return nil, ErrMissingPackageName
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return s.raw.Monetization.ConvertRegionPrices(packageName, req).Context(ctx).Do()
}

// BasePlansService wraps the subscriptions.basePlans sub-resource.
type BasePlansService struct {
	raw    *androidpublisher.Service
	Offers *OffersService
}

func (b *BasePlansService) Activate(ctx context.Context, packageName, productID, basePlanID string, req *androidpublisher.ActivateBasePlanRequest) (*androidpublisher.Subscription, error) {
	if err := b.validate(packageName, productID, basePlanID); err != nil {
		return nil, err
	}
	if req == nil {
		req = &androidpublisher.ActivateBasePlanRequest{}
	}
	return b.raw.Monetization.Subscriptions.BasePlans.Activate(packageName, productID, basePlanID, req).Context(ctx).Do()
}

func (b *BasePlansService) Deactivate(ctx context.Context, packageName, productID, basePlanID string, req *androidpublisher.DeactivateBasePlanRequest) (*androidpublisher.Subscription, error) {
	if err := b.validate(packageName, productID, basePlanID); err != nil {
		return nil, err
	}
	if req == nil {
		req = &androidpublisher.DeactivateBasePlanRequest{}
	}
	return b.raw.Monetization.Subscriptions.BasePlans.Deactivate(packageName, productID, basePlanID, req).Context(ctx).Do()
}

func (b *BasePlansService) Delete(ctx context.Context, packageName, productID, basePlanID string) error {
	if err := b.validate(packageName, productID, basePlanID); err != nil {
		return err
	}
	return b.raw.Monetization.Subscriptions.BasePlans.Delete(packageName, productID, basePlanID).Context(ctx).Do()
}

func (b *BasePlansService) MigratePrices(ctx context.Context, packageName, productID, basePlanID string, req *androidpublisher.MigrateBasePlanPricesRequest) (*androidpublisher.MigrateBasePlanPricesResponse, error) {
	if err := b.validate(packageName, productID, basePlanID); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return b.raw.Monetization.Subscriptions.BasePlans.MigratePrices(packageName, productID, basePlanID, req).Context(ctx).Do()
}

func (b *BasePlansService) BatchMigratePrices(ctx context.Context, packageName, productID string, req *androidpublisher.BatchMigrateBasePlanPricesRequest) (*androidpublisher.BatchMigrateBasePlanPricesResponse, error) {
	if b == nil || b.raw == nil {
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
	return b.raw.Monetization.Subscriptions.BasePlans.BatchMigratePrices(packageName, productID, req).Context(ctx).Do()
}

func (b *BasePlansService) BatchUpdateStates(ctx context.Context, packageName, productID string, req *androidpublisher.BatchUpdateBasePlanStatesRequest) (*androidpublisher.BatchUpdateBasePlanStatesResponse, error) {
	if b == nil || b.raw == nil {
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
	return b.raw.Monetization.Subscriptions.BasePlans.BatchUpdateStates(packageName, productID, req).Context(ctx).Do()
}

func (b *BasePlansService) validate(packageName, productID, basePlanID string) error {
	if b == nil || b.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if productID == "" {
		return ErrMissingProductID
	}
	if basePlanID == "" {
		return ErrMissingBasePlanID
	}
	return nil
}

// OffersService wraps the subscriptions.basePlans.offers sub-resource.
type OffersService struct {
	raw *androidpublisher.Service
}

func (o *OffersService) Get(ctx context.Context, packageName, productID, basePlanID, offerID string) (*androidpublisher.SubscriptionOffer, error) {
	if err := o.validate(packageName, productID, basePlanID, offerID); err != nil {
		return nil, err
	}
	return o.raw.Monetization.Subscriptions.BasePlans.Offers.Get(packageName, productID, basePlanID, offerID).Context(ctx).Do()
}

func (o *OffersService) List(ctx context.Context, packageName, productID, basePlanID string, opts ListOptions) (*androidpublisher.ListSubscriptionOffersResponse, error) {
	if err := o.validateParent(packageName, productID, basePlanID); err != nil {
		return nil, err
	}
	call := o.raw.Monetization.Subscriptions.BasePlans.Offers.List(packageName, productID, basePlanID).Context(ctx)
	if opts.PageSize > 0 {
		call = call.PageSize(opts.PageSize)
	}
	if opts.PageToken != "" {
		call = call.PageToken(opts.PageToken)
	}
	return call.Do()
}

func (o *OffersService) Create(ctx context.Context, packageName, productID, basePlanID string, offer *androidpublisher.SubscriptionOffer, opts CreateOptions) (*androidpublisher.SubscriptionOffer, error) {
	if err := o.validateParent(packageName, productID, basePlanID); err != nil {
		return nil, err
	}
	if offer == nil {
		return nil, ErrMissingOffer
	}
	call := o.raw.Monetization.Subscriptions.BasePlans.Offers.Create(packageName, productID, basePlanID, offer).Context(ctx)
	if opts.RegionsVersion != "" {
		call = call.RegionsVersionVersion(opts.RegionsVersion)
	}
	return call.Do()
}

func (o *OffersService) Patch(ctx context.Context, packageName, productID, basePlanID, offerID string, offer *androidpublisher.SubscriptionOffer, opts PatchOptions) (*androidpublisher.SubscriptionOffer, error) {
	if err := o.validate(packageName, productID, basePlanID, offerID); err != nil {
		return nil, err
	}
	if offer == nil {
		return nil, ErrMissingOffer
	}
	call := o.raw.Monetization.Subscriptions.BasePlans.Offers.Patch(packageName, productID, basePlanID, offerID, offer).Context(ctx)
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

func (o *OffersService) Delete(ctx context.Context, packageName, productID, basePlanID, offerID string) error {
	if err := o.validate(packageName, productID, basePlanID, offerID); err != nil {
		return err
	}
	return o.raw.Monetization.Subscriptions.BasePlans.Offers.Delete(packageName, productID, basePlanID, offerID).Context(ctx).Do()
}

func (o *OffersService) Activate(ctx context.Context, packageName, productID, basePlanID, offerID string, req *androidpublisher.ActivateSubscriptionOfferRequest) (*androidpublisher.SubscriptionOffer, error) {
	if err := o.validate(packageName, productID, basePlanID, offerID); err != nil {
		return nil, err
	}
	if req == nil {
		req = &androidpublisher.ActivateSubscriptionOfferRequest{}
	}
	return o.raw.Monetization.Subscriptions.BasePlans.Offers.Activate(packageName, productID, basePlanID, offerID, req).Context(ctx).Do()
}

func (o *OffersService) Deactivate(ctx context.Context, packageName, productID, basePlanID, offerID string, req *androidpublisher.DeactivateSubscriptionOfferRequest) (*androidpublisher.SubscriptionOffer, error) {
	if err := o.validate(packageName, productID, basePlanID, offerID); err != nil {
		return nil, err
	}
	if req == nil {
		req = &androidpublisher.DeactivateSubscriptionOfferRequest{}
	}
	return o.raw.Monetization.Subscriptions.BasePlans.Offers.Deactivate(packageName, productID, basePlanID, offerID, req).Context(ctx).Do()
}

func (o *OffersService) BatchGet(ctx context.Context, packageName, productID, basePlanID string, req *androidpublisher.BatchGetSubscriptionOffersRequest) (*androidpublisher.BatchGetSubscriptionOffersResponse, error) {
	if err := o.validateParent(packageName, productID, basePlanID); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return o.raw.Monetization.Subscriptions.BasePlans.Offers.BatchGet(packageName, productID, basePlanID, req).Context(ctx).Do()
}

func (o *OffersService) BatchUpdate(ctx context.Context, packageName, productID, basePlanID string, req *androidpublisher.BatchUpdateSubscriptionOffersRequest) (*androidpublisher.BatchUpdateSubscriptionOffersResponse, error) {
	if err := o.validateParent(packageName, productID, basePlanID); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return o.raw.Monetization.Subscriptions.BasePlans.Offers.BatchUpdate(packageName, productID, basePlanID, req).Context(ctx).Do()
}

func (o *OffersService) BatchUpdateStates(ctx context.Context, packageName, productID, basePlanID string, req *androidpublisher.BatchUpdateSubscriptionOfferStatesRequest) (*androidpublisher.BatchUpdateSubscriptionOfferStatesResponse, error) {
	if err := o.validateParent(packageName, productID, basePlanID); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrMissingRequest
	}
	return o.raw.Monetization.Subscriptions.BasePlans.Offers.BatchUpdateStates(packageName, productID, basePlanID, req).Context(ctx).Do()
}

func (o *OffersService) validateParent(packageName, productID, basePlanID string) error {
	if o == nil || o.raw == nil {
		return ErrServiceNil
	}
	if packageName == "" {
		return ErrMissingPackageName
	}
	if productID == "" {
		return ErrMissingProductID
	}
	if basePlanID == "" {
		return ErrMissingBasePlanID
	}
	return nil
}

func (o *OffersService) validate(packageName, productID, basePlanID, offerID string) error {
	if err := o.validateParent(packageName, productID, basePlanID); err != nil {
		return err
	}
	if offerID == "" {
		return ErrMissingOfferID
	}
	return nil
}
